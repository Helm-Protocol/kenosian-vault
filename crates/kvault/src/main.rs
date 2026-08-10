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
use kvault::seal::{self, Anchorer, HttpAnchorer, ReceiptFile, SealError};

const USAGE: &str = "\
kvault — Lean 증명을 자기 기계에서 검증하고, 통과분만 봉인한다.

사용법
  kvault login  <이메일> [--use-case <설명>]
  kvault check  <파일.lean> [옵션]
  kvault submit <파일.lean> [옵션]

  check   ① 로컬 커널 검증만. 서버를 부르지 않는다.
  submit  ① → ② 연속. kernel-standard 로 통과한 것만 봉인한다.
  login   키 발급(승인 없음, 무료 1,000 seal). ~/.config/kenosian/credentials 에 0600 으로 저장.

옵션
  --project <디렉토리>   lakefile 이 있는 곳. 생략하면 파일에서 위로 찾아 올라간다.
  --timeout <초>         lake 검증 상한 (기본 600)
  --http-timeout <초>    서버 응답 상한 (기본 30)
  --external-ref <문자열> 영수증을 나중에 찾기 위한 내 쪽 식별자 (submit)
  --require-chain-time   Roughtime 체인 시각이 아니면 봉인을 거절시킨다 (submit)
  --base-url <URL>       기본 https://kpp.kenosian.com
  --json                 판정을 JSON 한 덩어리로 stdout 에 낸다
  -h, --help / -V, --version

종료코드
  0 성공 · 1 검증 실패 · 2 봉인 실패(①검증은 그대로 유효) · 3 사용법/설정 오류

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
    let anchorer = HttpAnchorer::new(&url, key, http_timeout);

    submit_with(&report, &anchorer, o)
}

fn submit_with(report: &CheckReport, anchorer: &dyn Anchorer, o: &Opts) -> ExitCode {
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
            ExitCode::SUCCESS
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
