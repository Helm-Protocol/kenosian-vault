//! ① 로컬 검증 — 기여자 기계에서 커널을 돌린다. 서버를 부르지 않는다.
//!
//! ★이건 문지기가 아니라 필터다. 결과는 위조할 수 있다(이 바이너리를 고치면 그만이다).
//!   여기서 얻는 것은 5초 만에 아는 실패이고, 그게 실무에서 제일 크다.
//! ★Lean 을 번들하지 않는다. 이미 설치된 `lake` 를 부르고, 없으면 없다고 말한다.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use crate::comments::{count_axiom_decl, count_sorry, strip_comments};

/// Lean 4 커널 표준 공리. 이 셋만 쓰면 kernel-standard.
pub const STANDARD_AXIOMS: [&str; 3] = ["propext", "Classical.choice", "Quot.sound"];

/// 검증이 통과했을 때의 산출물.
#[derive(Debug, Clone)]
pub struct CheckReport {
    pub path: PathBuf,
    pub project_root: PathBuf,
    /// `#print axioms` 가 이름을 찍은 정리들. 첫 항목을 봉인의 theorem_id 로 쓴다.
    pub theorems: Vec<String>,
    pub axioms: Vec<String>,
    /// 통과한 것은 언제나 "kernel-standard" 다. 그 밖은 오류로 나간다.
    pub axiom_level: &'static str,
    pub elapsed: Duration,
}

/// 검증이 막힌 이유. `name()` 은 기계가 읽는 안정된 이름이다 —
/// ⛔조용한 실패 금지: 왜 막혔는지가 언제나 이름으로 남아야 한다.
#[derive(Debug, thiserror::Error)]
pub enum CheckError {
    #[error("파일을 읽을 수 없다: {path} ({source})")]
    FileUnreadable {
        path: String,
        #[source]
        source: std::io::Error,
    },

    #[error("소스에 sorry {sorry}건 · axiom 선언 {axiom}건 — 커널을 부르기 전에 걸린다")]
    SourceHasSorryOrAxiom { sorry: usize, axiom: usize },

    #[error(
        "lake 가 없다. Lean 4 툴체인이 필요하다 (elan 으로 설치). \
         Lean 없이 금고 조회만 하려면 pip install kenosian-vault 를 써라"
    )]
    LakeMissing,

    #[error("lakefile 을 못 찾았다 — --project <디렉토리> 로 지정해라 (찾은 곳: {searched_from})")]
    LakefileNotFound { searched_from: String },

    #[error("lake 실행 실패: {0}")]
    LakeSpawnFailed(#[source] std::io::Error),

    #[error("시간초과 {secs}s — 증명이 갇혔을 수 있다. --timeout 으로 늘려라")]
    LakeTimeout { secs: u64 },

    #[error("커널이 거부했다 (exit {code})")]
    KernelRejected { code: i32, stderr: String },

    #[error(
        "`#print axioms <정리이름>` 이 없다. 무엇에 의존하는지 찍어라 — 모르는 것은 통과가 아니다"
    )]
    NoAxiomPrint { stdout: String },

    #[error("축에 sorryAx 가 있다 — 증명이 닫히지 않았다 (축: {})", axioms.join(", "))]
    SorryAxInAxioms { axioms: Vec<String> },

    #[error(
        "compiler-trusted — 표준 3종 밖의 공리에 의존한다: {}. \
         대외 기준은 kernel-standard 뿐이라 여기서 멈춘다",
        extra.join(", ")
    )]
    CompilerTrusted { axioms: Vec<String>, extra: Vec<String> },
}

impl CheckError {
    pub fn name(&self) -> &'static str {
        match self {
            CheckError::FileUnreadable { .. } => "file_unreadable",
            CheckError::SourceHasSorryOrAxiom { .. } => "source_has_sorry_or_axiom",
            CheckError::LakeMissing => "lake_missing",
            CheckError::LakefileNotFound { .. } => "lakefile_not_found",
            CheckError::LakeSpawnFailed(_) => "lake_spawn_failed",
            CheckError::LakeTimeout { .. } => "lake_timeout",
            CheckError::KernelRejected { .. } => "kernel_rejected",
            CheckError::NoAxiomPrint { .. } => "no_axiom_print",
            CheckError::SorryAxInAxioms { .. } => "sorry_ax_in_axioms",
            CheckError::CompilerTrusted { .. } => "compiler_trusted",
        }
    }
}

/// 파일에서 위로 올라가며 `lakefile.lean` / `lakefile.toml` 을 찾는다.
pub fn find_project_root(file: &Path) -> Option<PathBuf> {
    let start = file.parent()?;
    for anc in start.ancestors() {
        if anc.join("lakefile.lean").is_file() || anc.join("lakefile.toml").is_file() {
            return Some(anc.to_path_buf());
        }
    }
    None
}

fn lake_on_path() -> bool {
    let path = match std::env::var_os("PATH") {
        Some(p) => p,
        None => return false,
    };
    std::env::split_paths(&path).any(|d| {
        let c = d.join("lake");
        c.is_file() || c.is_symlink()
    })
}

/// `.lean` 파일 하나를 로컬 커널로 검증한다.
pub fn check(
    file: &Path,
    project: Option<&Path>,
    timeout: Duration,
) -> Result<CheckReport, CheckError> {
    let started = Instant::now();

    let path = file
        .canonicalize()
        .map_err(|e| CheckError::FileUnreadable { path: file.display().to_string(), source: e })?;

    let src = std::fs::read(&path)
        .map_err(|e| CheckError::FileUnreadable { path: path.display().to_string(), source: e })?;
    let src = String::from_utf8_lossy(&src).into_owned();

    // ── 커널을 부르기 전에 소스부터 본다. 여기서 걸리면 몇 밀리초 만에 끝난다.
    let body = strip_comments(&src);
    let n_sorry = count_sorry(&body);
    let n_axiom = count_axiom_decl(&body);
    if n_sorry > 0 || n_axiom > 0 {
        return Err(CheckError::SourceHasSorryOrAxiom { sorry: n_sorry, axiom: n_axiom });
    }

    if !lake_on_path() {
        return Err(CheckError::LakeMissing);
    }

    let root = match project {
        Some(p) => p.canonicalize().map_err(|e| CheckError::FileUnreadable {
            path: p.display().to_string(),
            source: e,
        })?,
        None => find_project_root(&path).ok_or_else(|| CheckError::LakefileNotFound {
            searched_from: path.display().to_string(),
        })?,
    };

    let rel: PathBuf = path.strip_prefix(&root).map(Path::to_path_buf).unwrap_or_else(|_| path.clone());

    tracing::debug!(root = %root.display(), file = %rel.display(), "lake env lean");
    let out = run_lake(&root, &rel, timeout)?;

    let combined = format!("{}{}", out.stdout, out.stderr);
    if out.code != 0 {
        return Err(CheckError::KernelRejected { code: out.code, stderr: combined });
    }

    // ── `#print axioms` 출력 수집.
    // ⛔없으면 통과로 치지 않는다 — 축을 안 찍으면 무엇에 의존하는지 모르는 것이고,
    //   모르는 것은 통과가 아니다.
    let printed = parse_axiom_prints(&combined);
    if printed.theorems.is_empty() {
        return Err(CheckError::NoAxiomPrint { stdout: combined });
    }

    let mut axioms: Vec<String> = printed.axioms.into_iter().collect();
    axioms.sort();
    axioms.dedup();

    let extra: Vec<String> =
        axioms.iter().filter(|a| !STANDARD_AXIOMS.contains(&a.as_str())).cloned().collect();

    if extra.iter().any(|a| a == "sorryAx") {
        return Err(CheckError::SorryAxInAxioms { axioms });
    }
    if !extra.is_empty() {
        return Err(CheckError::CompilerTrusted { axioms, extra });
    }

    Ok(CheckReport {
        path,
        project_root: root,
        theorems: printed.theorems,
        axioms,
        axiom_level: "kernel-standard",
        elapsed: started.elapsed(),
    })
}

struct LakeOutput {
    code: i32,
    stdout: String,
    stderr: String,
}

/// `lake env lean <파일>` 을 돌린다. 파이프를 읽는 스레드를 따로 두어
/// 출력이 많아도 막히지 않게 하고, 마감시각을 넘기면 죽인다.
fn run_lake(root: &Path, rel: &Path, timeout: Duration) -> Result<LakeOutput, CheckError> {
    let mut child = Command::new("lake")
        .arg("env")
        .arg("lean")
        .arg(rel)
        .current_dir(root)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(CheckError::LakeSpawnFailed)?;

    let mut so = child.stdout.take();
    let mut se = child.stderr.take();
    let h_out = std::thread::spawn(move || {
        let mut s = String::new();
        if let Some(r) = so.as_mut() {
            let _ = r.read_to_string(&mut s);
        }
        s
    });
    let h_err = std::thread::spawn(move || {
        let mut s = String::new();
        if let Some(r) = se.as_mut() {
            let _ = r.read_to_string(&mut s);
        }
        s
    });

    let deadline = Instant::now() + timeout;
    let status = loop {
        match child.try_wait() {
            Ok(Some(st)) => break st,
            Ok(None) => {
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    let _ = h_out.join();
                    let _ = h_err.join();
                    return Err(CheckError::LakeTimeout { secs: timeout.as_secs() });
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(e) => return Err(CheckError::LakeSpawnFailed(e)),
        }
    };

    let stdout = h_out.join().unwrap_or_else(|_| String::new());
    let stderr = h_err.join().unwrap_or_else(|_| String::new());
    Ok(LakeOutput { code: status.code().unwrap_or(-1), stdout, stderr })
}

#[derive(Default)]
struct AxiomPrints {
    theorems: Vec<String>,
    axioms: Vec<String>,
}

/// Lean 이 찍는 두 형태를 읽는다.
///   `'NAME' depends on axioms: [a, b, c]`
///   `'NAME' does not depend on any axioms`
/// 목록은 줄바꿈으로 접힐 수 있어서 `]` 까지 그대로 읽는다.
fn parse_axiom_prints(raw: &str) -> AxiomPrints {
    const DEP: &str = "depends on axioms:";
    const NODEP: &str = "does not depend on any axioms";
    let mut r = AxiomPrints::default();

    for (idx, _) in raw.match_indices(DEP) {
        if let Some(name) = quoted_name_before(raw, idx) {
            r.theorems.push(name);
        }
        let after = &raw[idx + DEP.len()..];
        let after = after.trim_start();
        if let Some(rest) = after.strip_prefix('[') {
            if let Some(end) = rest.find(']') {
                for a in rest[..end].split(',') {
                    let a = a.trim();
                    if !a.is_empty() {
                        r.axioms.push(a.to_string());
                    }
                }
            }
        }
    }

    for (idx, _) in raw.match_indices(NODEP) {
        if let Some(name) = quoted_name_before(raw, idx) {
            r.theorems.push(name);
        }
    }

    r.theorems.sort();
    r.theorems.dedup();
    r
}

/// `idx` 바로 앞의 `'...'` 안 이름을 집는다.
fn quoted_name_before(raw: &str, idx: usize) -> Option<String> {
    let head = &raw[..idx];
    let close = head.rfind('\'')?;
    let open = head[..close].rfind('\'')?;
    let name = head[open + 1..close].trim();
    if name.is_empty() {
        None
    } else {
        Some(name.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_standard_three() {
        let raw = "'KLean.f_one_eq_zero' depends on axioms: [propext, Classical.choice, Quot.sound]\n";
        let p = parse_axiom_prints(raw);
        assert_eq!(p.theorems, vec!["KLean.f_one_eq_zero"]);
        assert_eq!(p.axioms, vec!["propext", "Classical.choice", "Quot.sound"]);
    }

    #[test]
    fn parses_native_decide() {
        let raw = "'A.b' depends on axioms: [propext, Classical.choice, Quot.sound, Lean.ofReduceBool]";
        let p = parse_axiom_prints(raw);
        assert!(p.axioms.contains(&"Lean.ofReduceBool".to_string()));
        let extra: Vec<&String> =
            p.axioms.iter().filter(|a| !STANDARD_AXIOMS.contains(&a.as_str())).collect();
        assert_eq!(extra, vec!["Lean.ofReduceBool"]);
    }

    #[test]
    fn parses_no_axioms_form() {
        let p = parse_axiom_prints("'A.trivial_thm' does not depend on any axioms\n");
        assert_eq!(p.theorems, vec!["A.trivial_thm"]);
        assert!(p.axioms.is_empty());
    }

    #[test]
    fn parses_wrapped_list() {
        let raw = "'A.b' depends on axioms: [propext,\n Classical.choice,\n Quot.sound]\n";
        let p = parse_axiom_prints(raw);
        assert_eq!(p.axioms.len(), 3);
    }

    #[test]
    fn empty_output_yields_nothing() {
        assert!(parse_axiom_prints("").theorems.is_empty());
    }
}
