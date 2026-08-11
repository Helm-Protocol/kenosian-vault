//! `kvault` CLI.
//!
//! ★stdout 은 산출물이다(사용자에게 보여주는 판정·영수증). stderr 은 진단 로그다.
//!   둘을 섞지 않는다 — 파이프로 받아 쓰는 쪽이 로그에 오염되면 안 된다.
//! ★panic 하지 않는다. main 은 exit code 로 말한다.
//!   0 성공 · 1 검증 실패 · 2 봉인 실패(검증은 유효) · 3 사용법/설정 오류.

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use kvault::check::{self, CheckError, CheckReport};
use kvault::creds;
use kvault::publish;
use kvault::seal::{self, Anchorer, HttpAnchorer, ReceiptFile, SealError};

const USAGE: &str = "\
kvault — Lean 증명을 자기 기계에서 검증하고, 통과분만 봉인한다.

사용법
  kvault login  <이메일> [--use-case <설명>]
  kvault check  <파일.lean> [옵션]
  kvault submit <파일.lean> [옵션]

  check   ① 로컬 커널 검증만. 서버를 부르지 않는다.
  submit  ① → ② 연속. kernel-standard 로 통과한 것만 봉인한다.
          --publish 를 주면 ③ 까지 — 봉인된 그 바이트를 저장소에 PR 로 올린다.
          ★서버는 ③ 에서도 Lean 을 돌리지 않는다. 해시 대조뿐이고, 병합은 사람이 한다.
  login   키 발급(승인 없음, 무료 1,000 seal). ~/.config/kenosian/credentials 에 0600 으로 저장.

옵션
  --project <디렉토리>   lakefile 이 있는 곳. 생략하면 파일에서 위로 찾아 올라간다.
  --timeout <초>         lake 검증 상한 (기본 600)
  --http-timeout <초>    서버 응답 상한 (기본 30)
  --external-ref <문자열> 영수증을 나중에 찾기 위한 내 쪽 식별자 (submit)
  --require-chain-time   Roughtime 체인 시각이 아니면 봉인을 거절시킨다 (submit)
  --publish              ③ 등재까지 간다 (submit)
  --path <저장소경로>     등재 위치. 생략하면 파일 경로의 `KLean/` 부터를 쓴다 (--publish)
  --note <한 줄>          PR 본문에 남길 검토자용 한 줄 (--publish)
  --base-url <URL>       기본 https://kpp.kenosian.com
  --json                 판정을 JSON 한 덩어리로 stdout 에 낸다
  -h, --help / -V, --version

종료코드
  0 성공 · 1 검증 실패 · 2 봉인 실패(①검증은 그대로 유효) · 3 사용법/설정 오류
  4 등재 실패(①검증·②봉인은 그대로 유효)

로그
  진단은 stderr 로 나간다. KVAULT_LOG=debug 로 자세히 볼 수 있다.
";

#[derive(Debug, Default)]
struct Opts {
    project: Option<PathBuf>,
    timeout: Option<u64>,
    http_timeout: Option<u64>,
    external_ref: Option<String>,
    use_case: Option<String>,
    require_chain_time: bool,
    base_url: Option<String>,
    json: bool,
    publish: bool,
    path: Option<String>,
    note: Option<String>,
}

fn main() -> ExitCode {
    init_logging();

    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() {
        print!("{USAGE}");
        return ExitCode::from(3);
    }
    match args[0].as_str() {
        "-h" | "--help" | "help" => {
            print!("{USAGE}");
            return ExitCode::SUCCESS;
        }
        "-V" | "--version" => {
            println!("kvault {}", kvault::VERSION);
            return ExitCode::SUCCESS;
        }
        _ => {}
    }

    let (positional, opts) = match parse_args(&args[1..]) {
        Ok(v) => v,
        Err(msg) => {
            eprintln!("kvault: {msg}\n");
            print!("{USAGE}");
            return ExitCode::from(3);
        }
    };

    match args[0].as_str() {
        "login" => cmd_login(&positional, &opts),
        "check" => cmd_check(&positional, &opts),
        "submit" => cmd_submit(&positional, &opts),
        other => {
            eprintln!("kvault: 모르는 명령 '{other}'\n");
            print!("{USAGE}");
            ExitCode::from(3)
        }
    }
}

fn init_logging() {
    let level = match std::env::var("KVAULT_LOG").as_deref() {
        Ok("trace") => tracing::Level::TRACE,
        Ok("debug") => tracing::Level::DEBUG,
        Ok("info") => tracing::Level::INFO,
        Ok("error") => tracing::Level::ERROR,
        _ => tracing::Level::WARN,
    };
    // try_init 은 이미 설정돼 있어도 panic 하지 않는다.
    let _ = tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_max_level(level)
        .with_target(false)
        .without_time()
        .try_init();
}

fn parse_args(args: &[String]) -> Result<(Vec<String>, Opts), String> {
    let mut pos = Vec::new();
    let mut o = Opts::default();
    let mut i = 0usize;
    while i < args.len() {
        let a = args[i].as_str();
        let need = |name: &str, i: &mut usize| -> Result<String, String> {
            *i += 1;
            args.get(*i).cloned().ok_or_else(|| format!("{name} 에 값이 필요하다"))
        };
        match a {
            "--project" => o.project = Some(PathBuf::from(need("--project", &mut i)?)),
            "--timeout" => {
                let v = need("--timeout", &mut i)?;
                o.timeout = Some(v.parse().map_err(|_| format!("--timeout 은 초 단위 숫자다: {v}"))?);
            }
            "--http-timeout" => {
                let v = need("--http-timeout", &mut i)?;
                o.http_timeout =
                    Some(v.parse().map_err(|_| format!("--http-timeout 은 초 단위 숫자다: {v}"))?);
            }
            "--external-ref" => o.external_ref = Some(need("--external-ref", &mut i)?),
            "--use-case" => o.use_case = Some(need("--use-case", &mut i)?),
            "--base-url" => o.base_url = Some(need("--base-url", &mut i)?),
            "--require-chain-time" => o.require_chain_time = true,
            "--publish" => o.publish = true,
            "--path" => o.path = Some(need("--path", &mut i)?),
            "--note" => o.note = Some(need("--note", &mut i)?),
            "--json" => o.json = true,
            other if other.starts_with('-') => return Err(format!("모르는 옵션 '{other}'")),
            other => pos.push(other.to_string()),
        }
        i += 1;
    }
    Ok((pos, o))
}

fn base_url(o: &Opts) -> String {
    o.base_url
        .clone()
        .or_else(|| std::env::var("KENOSIAN_BASE_URL").ok())
        .unwrap_or_else(|| seal::DEFAULT_BASE_URL.to_string())
}

// ─────────────────────────────────────────────────────────── login

fn cmd_login(pos: &[String], o: &Opts) -> ExitCode {
    let email = match pos.first() {
        Some(e) => e,
        None => {
            eprintln!("kvault: login 에 이메일이 필요하다 — kvault login you@example.com");
            return ExitCode::from(3);
        }
    };
    let url = base_url(o);
    let timeout = Duration::from_secs(o.http_timeout.unwrap_or(30));
    let use_case = o.use_case.clone().unwrap_or_else(|| "lean proof sealing via kvault".into());

    match seal::mint_key(&url, email, &use_case, timeout) {
        Ok(k) => {
            let secret = secrecy::SecretString::from(k.api_key.clone());
            match creds::save_key(&secret, &k.key_id, email) {
                Ok(path) => {
                    // ⛔원문 키를 찍지 않는다. 파일에만 들어간다.
                    println!("LOGGED IN");
                    println!("  key_id     {}", k.key_id);
                    println!("  quota      {} seal (사용 {})", k.quota, k.used);
                    println!("  saved      {} (mode 0600)", path.display());
                    println!("  note       {}", k.message);
                    println!("  ★원문 키는 이 파일에만 있다. 서버는 sha256 만 갖고 있어 재발급이 유일한 복구다.");
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("kvault: 키는 발급됐는데 저장에 실패했다 [{}] {e}", e.name());
                    ExitCode::from(3)
                }
            }
        }
        Err(e) => {
            eprintln!("kvault: 키 발급 실패 [{}] {e}", e.name());
            ExitCode::from(2)
        }
    }
}

// ─────────────────────────────────────────────────────────── check

fn cmd_check(pos: &[String], o: &Opts) -> ExitCode {
    let file = match pos.first() {
        Some(f) => PathBuf::from(f),
        None => {
            eprintln!("kvault: check 에 .lean 파일이 필요하다");
            return ExitCode::from(3);
        }
    };
    let timeout = Duration::from_secs(o.timeout.unwrap_or(600));

    match check::check(&file, o.project.as_deref(), timeout) {
        Ok(r) => {
            if o.json {
                print_check_json(&r, None);
            } else {
                print_check_human(&r);
            }
            ExitCode::SUCCESS
        }
        Err(e) => {
            report_check_error(&file, &e, o.json);
            ExitCode::from(1)
        }
    }
}

fn print_check_human(r: &CheckReport) {
    println!("PASS  {}", r.axiom_level);
    println!("  file      {}", r.path.display());
    println!("  project   {}", r.project_root.display());
    for t in &r.theorems {
        println!("  theorem   {t}");
    }
    println!("  axioms    {}", r.axioms.join(", "));
    match seal::sha256_file(&r.path) {
        Ok(d) => println!("  sha256    {d}"),
        Err(e) => println!("  sha256    (읽지 못했다: {e})"),
    }
    println!("  elapsed   {:.1}s", r.elapsed.as_secs_f64());
}

fn print_check_json(r: &CheckReport, sealed: Option<&seal::Sealed>) {
    let digest = seal::sha256_file(&r.path).unwrap_or_else(|_| String::new());
    let mut v = serde_json::json!({
        "ok": true,
        "file": r.path.display().to_string(),
        "project": r.project_root.display().to_string(),
        "axiom_level": r.axiom_level,
        "axioms": r.axioms,
        "theorems": r.theorems,
        "sha256": digest,
        "elapsed_s": r.elapsed.as_secs_f64(),
    });
    if let (Some(s), Some(obj)) = (sealed, v.as_object_mut()) {
        obj.insert(
            "anchor".into(),
            serde_json::to_value(&s.response).unwrap_or(serde_json::Value::Null),
        );
    }
    println!("{v}");
}

fn report_check_error(file: &Path, e: &CheckError, json: bool) {
    if json {
        let v = serde_json::json!({
            "ok": false,
            "stage": "check",
            "error": e.name(),
            "message": e.to_string(),
            "file": file.display().to_string(),
        });
        println!("{v}");
        return;
    }
    println!("FAIL  [{}]", e.name());
    println!("  file      {}", file.display());
    for line in e.to_string().lines() {
        println!("  이유      {line}");
    }
    // 커널이 거부한 경우엔 원문을 그대로 보여준다 — 멈추라고 말하는 도구는
    // 무엇 때문에 멈췄는지도 같이 남겨야 한다.
    if let CheckError::KernelRejected { stderr, .. } = e {
        println!("  ── lake 원문 ──");
        for line in stderr.lines() {
            println!("  {line}");
        }
    }
    if let CheckError::NoAxiomPrint { stdout } = e {
        if !stdout.trim().is_empty() {
            println!("  ── lake 원문 ──");
            for line in stdout.lines() {
                println!("  {line}");
            }
        }
    }
}

// ─────────────────────────────────────────────────────────── submit

fn cmd_submit(pos: &[String], o: &Opts) -> ExitCode {
    let file = match pos.first() {
        Some(f) => PathBuf::from(f),
        None => {
            eprintln!("kvault: submit 에 .lean 파일이 필요하다");
            return ExitCode::from(3);
        }
    };
    let timeout = Duration::from_secs(o.timeout.unwrap_or(600));

    // ★등재 경로는 봉인보다 먼저 정한다. 봉인은 quota 를 깎으므로, 어차피 올리지 못할
    //   것을 봉인해 놓고 마지막에 "경로를 모르겠다" 고 말하면 사용자가 seal 을 잃는다.
    let repo_rel = if o.publish {
        match o.path.clone().or_else(|| publish::repo_path(&file)) {
            Some(p) => Some(p),
            None => {
                eprintln!(
                    "kvault: [publish_path_undetermined] 저장소 안에서의 경로를 정할 수 없다 — {}\n  \
                     경로에 `KLean/` 이 없다. `--path KLean/...` 로 직접 지정해라.",
                    file.display()
                );
                return ExitCode::from(3);
            }
        }
    } else {
        None
    };

    // ① 검증. 여기서 막히면 서버를 부르지 않는다.
    let report = match check::check(&file, o.project.as_deref(), timeout) {
        Ok(r) => r,
        Err(e) => {
            report_check_error(&file, &e, o.json);
            return ExitCode::from(1);
        }
    };
    if !o.json {
        print_check_human(&report);
        println!();
    }

    // ② 봉인.
    let key = match creds::load_key() {
        Ok(k) => k,
        Err(e) => return seal_failed(&report, &SealError::Credentials(e), o.json),
    };
    let url = base_url(o);
    let http_timeout = Duration::from_secs(o.http_timeout.unwrap_or(30));
    let anchorer = HttpAnchorer::new(&url, key.clone(), http_timeout);

    submit_with(&report, &anchorer, o, repo_rel.map(|p| (p, key, url, http_timeout)))
}

type PublishCtx = (String, secrecy::SecretString, String, Duration);

fn submit_with(
    report: &CheckReport,
    anchorer: &dyn Anchorer,
    o: &Opts,
    publish_ctx: Option<PublishCtx>,
) -> ExitCode {
    let theorem_id = report.theorems.first().cloned();
    let sealed = seal::seal_file(
        &report.path,
        anchorer,
        theorem_id,
        o.external_ref.clone(),
        o.require_chain_time,
    );

    match sealed {
        Ok(s) => {
            let rf = ReceiptFile {
                kvault_version: kvault::VERSION,
                file: report.path.display().to_string(),
                valid: true,
                void_reason: None,
                content_hash: s.content_hash.clone(),
                content_hash_after: None,
                axiom_level: Some(report.axiom_level),
                axioms: report.axioms.clone(),
                theorems: report.theorems.clone(),
                anchor: s.response.clone(),
            };
            let written = seal::write_receipt(&report.path, &rf);

            if o.json {
                print_check_json(report, Some(&s));
            } else {
                println!("SEALED");
                println!("  receipt_id   {}", s.response.receipt_id);
                println!("  content_hash {}", s.content_hash);
                println!("  time         {}", s.response.time);
                println!("  time_source  {}", s.response.time_source);
                println!("  backdating_p {}", s.response.backdating_p);
                println!("  verify       {}", s.response.verify_url);
                println!("  quota        {} / {} (남은 {})", s.response.used, s.response.quota, s.response.remaining);
                match &written {
                    Ok(p) => println!("  receipt      {}", p.display()),
                    Err(e) => println!("  receipt      (저장 실패 [{}] {e})", e.name()),
                }
                if s.response.time_source != "roughtime_chain" {
                    println!(
                        "  ⚠ time_source 가 '{}' 다 — 체인 시각이 아니다. \
                         체인 시각이 아니면 봉인을 거절시키려면 --require-chain-time 을 써라.",
                        s.response.time_source
                    );
                }
            }
            if written.is_err() {
                return ExitCode::from(2);
            }
            match publish_ctx {
                None => ExitCode::SUCCESS,
                Some((repo_rel, key, url, http_timeout)) => publish_step(
                    report, &s, &repo_rel, &key, &url, http_timeout, o,
                ),
            }
        }
        Err(e) => {
            // ★해시가 바뀐 경우: 영수증은 이미 발급됐고 seal 도 차감됐다.
            //   기록은 남기되 무효라고 못 박는다.
            if let SealError::HashChangedDuringSeal { before, after, receipt } = &e {
                let rf = ReceiptFile {
                    kvault_version: kvault::VERSION,
                    file: report.path.display().to_string(),
                    valid: false,
                    void_reason: Some("hash_changed_during_seal"),
                    content_hash: before.clone(),
                    content_hash_after: Some(after.clone()),
                    axiom_level: Some(report.axiom_level),
                    axioms: report.axioms.clone(),
                    theorems: report.theorems.clone(),
                    anchor: (**receipt).clone(),
                };
                match seal::write_receipt(&report.path, &rf) {
                    Ok(p) => eprintln!("kvault: 무효 영수증을 기록했다 — {}", p.display()),
                    Err(w) => eprintln!("kvault: 무효 영수증 저장 실패 [{}] {w}", w.name()),
                }
            }
            seal_failed(report, &e, o.json)
        }
    }
}

// ─────────────────────────────────────────────────────────── publish (③)

/// ③ 등재. ★봉인이 성공한 뒤에만 불린다 — 봉인되지 않은 것은 올릴 수 없다.
///
/// 여기서 파일을 다시 읽어 해시를 한 번 더 센다. 봉인 때의 재계산과 겹쳐 보이지만,
/// 봉인과 등재 사이에도 시간이 흐르고 그 사이에 파일이 바뀔 수 있다. 대조를 파는
/// 물건이라면 대조가 성립하는 순간을 매번 다시 확인해야 한다.
fn publish_step(
    report: &CheckReport,
    sealed: &seal::Sealed,
    repo_rel: &str,
    key: &secrecy::SecretString,
    base: &str,
    timeout: Duration,
    o: &Opts,
) -> ExitCode {
    let result = publish::publish(
        &report.path,
        repo_rel,
        &sealed.response.receipt_id,
        &sealed.content_hash,
        Some(report.axiom_level),
        o.note.as_deref(),
        base,
        key,
        timeout,
    );

    match result {
        Ok(r) => {
            if o.json {
                let v = serde_json::json!({
                    "ok": true,
                    "stage": "publish",
                    "pr_url": r.pr_url,
                    "branch": r.branch,
                    "path": r.path,
                    "content_hash": r.content_hash,
                    "receipt_id": r.receipt_id,
                    "sealed_at": r.sealed_at,
                    "message": r.message,
                });
                println!("{v}");
            } else {
                println!();
                println!("PUBLISHED");
                println!("  pr           {}", r.pr_url);
                println!("  branch       {}", r.branch);
                println!("  path         {}", r.path);
                println!("  content_hash {}", r.content_hash);
                println!("  ★병합은 사람이 한다. 서버는 해시만 대조했고 Lean 은 돌리지 않았다.");
            }
            ExitCode::SUCCESS
        }
        Err(e) => {
            if o.json {
                let v = serde_json::json!({
                    "ok": false,
                    "stage": "publish",
                    "error": e.name(),
                    "message": e.to_string(),
                    "receipt_id": sealed.response.receipt_id,
                    "content_hash": sealed.content_hash,
                    "note": "①검증과 ②봉인은 끝났다. 영수증은 그대로 유효하다.",
                });
                println!("{v}");
            } else {
                println!();
                println!("PUBLISH FAILED  [{}]", e.name());
                for line in e.to_string().lines() {
                    println!("  {line}");
                }
                println!(
                    "  ★①검증과 ②봉인은 끝났다 — 영수증 {} 은 그대로 유효하다.",
                    sealed.response.receipt_id
                );
            }
            ExitCode::from(4)
        }
    }
}

fn seal_failed(report: &CheckReport, e: &SealError, json: bool) -> ExitCode {
    if json {
        let v = serde_json::json!({
            "ok": false,
            "stage": "seal",
            "error": e.name(),
            "message": e.to_string(),
            "file": report.path.display().to_string(),
            "check": {
                "ok": true,
                "axiom_level": report.axiom_level,
                "axioms": report.axioms,
                "theorems": report.theorems,
            },
            "note": "① 검증은 로컬에서 끝났고 서버와 무관하다. 그 판정은 그대로 유효하다.",
        });
        println!("{v}");
        return ExitCode::from(2);
    }
    println!("SEAL FAILED  [{}]", e.name());
    for line in e.to_string().lines() {
        println!("  {line}");
    }
    println!(
        "  ★① 검증은 이 기계에서 끝났고 서버와 무관하다 — {} 판정은 그대로 유효하다.",
        report.axiom_level
    );
    ExitCode::from(2)
}
