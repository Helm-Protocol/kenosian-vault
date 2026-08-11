//! Kenosian Vault 조회 클라이언트 — 정리가 Lean 4 커널을 통과했는지 물어본다.
//!
//! ```no_run
//! use kenosian_vault::Vault;
//!
//! let v = Vault::new();
//! let c = v.verify("KLean.Atoms.Bio.BiologicalAgeAtom.weighted_sum_nonneg").unwrap();
//! println!("{:?} {:?}", c.verified, c.axiom_level); // Some(true) Some("kernel-standard")
//! ```
//!
//! ★Lean 툴체인을 번들하지 않는다. 이건 HTTP 클라이언트이고 `cargo add` 가 1초다.
//!   이 크레이트는 `kpp.kenosian.com` 이 CI 에서 이미 커널로 검증해 둔 판정을
//!   O(1) 로 조회할 뿐이다 — 요청마다 서버가 증명을 다시 돌리지 않는다
//!   (2코어 서버에서 요청당 커널 실행은 DoS·5.15초 지연 이유로 기각됨).
//!
//! [`Vault::verify`] 라는 이름이 실시간 재검증처럼 들릴 수 있지만 그렇지 않다 —
//! [`Vault::theorem`] 의 별칭일 뿐이며, 이 크레이트가 하는 유일한 일은 HTTP GET
//! 하나로 이미 봉인된 결과를 가져오는 것이다.
//!
//! 이 모듈은 정본 Python 클라이언트(`src/kenosian_vault/client.py`)와 스키마와
//! 동작을 1:1로 미러링한다. 파이썬 쪽 규칙과 동일: `verified` 는 `bool` 이 아니라
//! **`Option<bool>`** 이다. `None` 은 "이 커밋의 `.olean` 에 없다 = 모른다"이지
//! "거짓"이 아니다. 이 삼중상태를 뭉개면 근거 없이 `true` 를 파는 것과 같아진다.

use std::time::Duration;

use serde::Deserialize;

/// 기본 API 베이스 URL.
pub const DEFAULT_BASE: &str = "https://kpp.kenosian.com";

const UA_HEADER: &str = concat!("kenosian-vault-rs/", env!("CARGO_PKG_VERSION"));
const COMMIT_HEADER: &str = "x-klv-commit-hash";
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);

/// 조회 실패. ⛔이유를 삼키지 않는다 — 조용한 강등이 제일 나쁘다.
///
/// `expect_commit` 이 걸린 상태에서 서빙 커밋이 다르면 [`VaultError::Stale`] 이 온다
/// (Python 쪽 `StaleVaultError` 와 동일한 자리 — Rust 에서는 별도 타입 대신 이
/// 열거형 variant 로 표현한다). [`VaultError::is_stale`] 로 구분해라.
#[derive(Debug, thiserror::Error)]
pub enum VaultError {
    /// 요청한 자원이 금고에 없다 (HTTP 404).
    #[error("금고에 없다: {0}")]
    NotFound(String),
    /// 2xx/404 이외의 HTTP 상태.
    #[error("HTTP {status} — {url}")]
    Http { status: u16, url: String },
    /// 연결/전송 실패 (DNS, TLS, 타임아웃 등).
    #[error("연결 실패 {url}: {reason}")]
    Connection { url: String, reason: String },
    /// 응답 본문이 기대한 JSON 스키마가 아니다.
    #[error("JSON 아님 {url}: {source}")]
    Json {
        url: String,
        #[source]
        source: serde_json::Error,
    },
    /// 서빙 중인 커밋이 `expect_commit` 과 다르다. 감사 중이라면 여기서 멈춰야 한다 —
    /// 금고가 그새 앞서가면 조용히 다른 시점의 답을 받게 되므로.
    #[error(
        "서빙 커밋 {served} != 기대 {expected}. 금고가 앞서갔다 — \
         같은 시점을 보려면 manifest 를 쓰거나 expect_commit 을 갱신해라."
    )]
    Stale { served: String, expected: String },
}

impl VaultError {
    /// 이 실패가 커밋 불일치(`Stale`)인지. Python 의 `except StaleVaultError`
    /// 대신 이 헬퍼로 분기한다.
    pub fn is_stale(&self) -> bool {
        matches!(self, VaultError::Stale { .. })
    }
}

/// 정리 하나의 검증서.
///
/// ⛔`verified` 는 `true`/`false` 가 아니라 **`Some(true)`/`None`** 이다.
/// `.olean` 이 그 커밋에 없으면 "모른다"이지 "거짓"이 아니다. 이 구분을 없애면
/// 근거 없이 `true` 를 파는 것과 같아진다(2026-08-08 규칙, Python 클라이언트와 동일).
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct Certificate {
    pub fqn: String,
    #[serde(default)]
    pub verified: Option<bool>,
    #[serde(default)]
    pub axiom_level: Option<String>,
    #[serde(default)]
    pub olean_sha256: Option<String>,
    #[serde(default)]
    pub module: Option<String>,
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub claim: Option<String>,
    #[serde(default)]
    pub quarantined: bool,
    #[serde(default)]
    pub statement: Option<String>,
    #[serde(default)]
    pub refs: Vec<String>,
    #[serde(default)]
    pub topics: Vec<String>,
    #[serde(default)]
    pub depends_on: Vec<String>,
    #[serde(default)]
    pub used_by: Vec<String>,
    #[serde(default)]
    pub compute: Option<String>,
    #[serde(default)]
    pub seal: Option<serde_json::Value>,
    #[serde(default)]
    pub commit: String,
}

impl Certificate {
    /// 표준 공리만 쓰는가. `native_decide` 가 섞이면 compiler-trusted 로
    /// 강등되고, 이 함수는 `false` 를 돌려준다.
    pub fn kernel_standard(&self) -> bool {
        self.axiom_level.as_deref() == Some("kernel-standard")
    }
}

/// `kpp.kenosian.com/v1/klv/*` 를 부르는 얇은 블로킹 클라이언트.
///
/// `expect_commit` 을 주면 서빙이 그 커밋이 아닐 때 [`VaultError::Stale`] 을
/// 돌려준다. 감사자가 특정 시점을 검증할 때 쓴다.
pub struct Vault {
    agent: ureq::Agent,
    base: String,
    expect_commit: Option<String>,
}

impl Default for Vault {
    fn default() -> Self {
        Vault::new()
    }
}

impl Vault {
    /// 기본 베이스(`DEFAULT_BASE`), 10초 타임아웃, `expect_commit` 없이 생성.
    pub fn new() -> Self {
        Vault::with_options(DEFAULT_BASE, DEFAULT_TIMEOUT, None)
    }

    /// 베이스 URL만 바꾼다. 나머지는 기본값.
    pub fn with_base(base: &str) -> Self {
        Vault::with_options(base, DEFAULT_TIMEOUT, None)
    }

    /// 특정 커밋에 핀 고정한다. 서빙 커밋이 다르면 이후 모든 호출이
    /// [`VaultError::Stale`] 을 돌려준다.
    pub fn with_expect_commit(expect_commit: &str) -> Self {
        Vault::with_options(DEFAULT_BASE, DEFAULT_TIMEOUT, Some(expect_commit))
    }

    /// 베이스/타임아웃/기대 커밋을 전부 지정하는 완전한 생성자.
    pub fn with_options(base: &str, timeout: Duration, expect_commit: Option<&str>) -> Self {
        let config = ureq::Agent::config_builder()
            .timeout_global(Some(timeout))
            // 4xx/5xx 를 Err 로 바꾸지 않는다. 본문을 직접 읽고 우리가 이유에
            // 이름을 붙인다 (kvault 와 동일한 선택).
            .http_status_as_error(false)
            .user_agent(UA_HEADER)
            .build();
        Vault {
            agent: ureq::Agent::new_with_config(config),
            base: base.trim_end_matches('/').to_string(),
            expect_commit: expect_commit.map(str::to_string),
        }
    }

    // ── 내부 ────────────────────────────────────────────────────────────

    fn get(&self, path: &str) -> Result<serde_json::Value, VaultError> {
        let url = format!("{}{}", self.base, path);

        let resp = self
            .agent
            .get(&url)
            .header("Accept", "application/json")
            .call()
            .map_err(|e| VaultError::Connection {
                url: url.clone(),
                reason: e.to_string(),
            })?;

        let status = resp.status().as_u16();
        let served = resp
            .headers()
            .get(COMMIT_HEADER)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();

        let mut resp = resp;
        let body_text = resp
            .body_mut()
            .read_to_string()
            .map_err(|e| VaultError::Connection {
                url: url.clone(),
                reason: e.to_string(),
            })?;

        match status {
            200 => {}
            404 => return Err(VaultError::NotFound(path.to_string())),
            s => return Err(VaultError::Http { status: s, url }),
        }

        let body: serde_json::Value =
            serde_json::from_str(&body_text).map_err(|e| VaultError::Json {
                url: url.clone(),
                source: e,
            })?;

        if let Some(expected) = &self.expect_commit {
            if !served.is_empty() && &served != expected {
                return Err(VaultError::Stale {
                    served,
                    expected: expected.clone(),
                });
            }
        }

        Ok(body)
    }

    // ── 공개 API ────────────────────────────────────────────────────────

    /// 정리 하나의 검증서. 없으면 [`VaultError::NotFound`].
    pub fn theorem(&self, fqn: &str) -> Result<Certificate, VaultError> {
        let path = format!("/v1/klv/theorem/{}", percent_encode(fqn));
        let body = self.get(&path)?;
        serde_json::from_value(body).map_err(|e| VaultError::Json {
            url: format!("{}{}", self.base, path),
            source: e,
        })
    }

    /// [`Vault::theorem`] 의 별칭. ⛔이름이 실시간 검증처럼 들리지만 그렇지
    /// 않다 — 이 호출도 HTTP GET 하나뿐이다. 커널은 CI 에서 이미 돌았고,
    /// 여기서는 그 판정을 O(1) 로 조회할 뿐이다. 호출부에서 "검증한다"는
    /// 직관적인 이름을 쓰고 싶을 때 이걸 부른다.
    pub fn verify(&self, fqn: &str) -> Result<Certificate, VaultError> {
        self.theorem(fqn)
    }

    /// 금고 집계와 서빙 커밋을 원본 JSON 그대로 돌려준다.
    pub fn stats(&self) -> Result<serde_json::Value, VaultError> {
        self.get("/v1/klv/stats")
    }

    /// 이 모듈이 바뀌면 다시 봐야 하는 모듈들 (역방향 DAG).
    ///
    /// 빈 목록은 "잎 모듈"이라는 뜻이지 "없다"는 뜻이 아니다 — 없으면
    /// [`VaultError::NotFound`] 가 난다.
    pub fn impact(&self, module: &str) -> Result<Vec<String>, VaultError> {
        let path = format!("/v1/klv/impact/{}", percent_encode(module));
        let body = self.get(&path)?;
        Ok(body
            .get("dependents")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|x| x.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default())
    }

    /// 지금 서빙 중인 금고 커밋. `stats()` 의 편의 래퍼.
    pub fn served_commit(&self) -> Result<String, VaultError> {
        let stats = self.stats()?;
        Ok(stats
            .get("commit")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string())
    }
}

/// RFC 3986 unreserved set(`ALPHA / DIGIT / "-" / "." / "_" / "~"`)만 그대로
/// 두고 나머지를 퍼센트 인코딩한다. Python `urllib.parse.quote(s, safe='')` 와
/// 동일한 규칙 — fqn/module 경로 세그먼트에 쓴다.
fn percent_encode(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for byte in input.as_bytes() {
        match *byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(*byte as char);
            }
            _ => {
                out.push('%');
                out.push_str(&format!("{byte:02X}"));
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 라이브 API 실측 응답(2026-08-11, `curl https://kpp.kenosian.com/v1/klv/theorem/…`
    /// commit `d2e7d1d`). 필드 이름을 추측하지 않고 실제 응답 모양 그대로 고정했다.
    /// `short` 필드는 서버가 주지만 Certificate 스키마에는 없다 — 미지정 필드는
    /// 조용히 무시되는지도 이 테스트가 같이 확인한다.
    const LIVE_FIXTURE: &str = r#"{
        "fqn": "KLean.CS.Golay23HammingBound.golay23_shannon_hamming_bound",
        "short": "golay23_shannon_hamming_bound",
        "module": "KLean.CS.Golay23HammingBound",
        "path": "KLean/CS/Golay23HammingBound.lean",
        "claim": "The binary Golay code [23,12,7] meets the Hamming sphere-packing bound with equality.",
        "verified": true,
        "axiom_level": "kernel-standard",
        "olean_sha256": "723ce9d6d28191ff39eb039bc32fcf0643b8edb0453742b7c0b55c58b6d49091",
        "quarantined": false,
        "statement": "theorem golay23_shannon_hamming_bound : 2 ^ 12 * (Nat.choose 23 0 + Nat.choose 23 1 + Nat.choose 23 2 + Nat.choose 23 3) = 2 ^ 23",
        "topics": ["coding-theory", "computation", "information", "moonshine"],
        "refs": ["https://doi.org/10.1109/JRPROC.1949.233620"],
        "depends_on": [
            "KLean.CS.Golay23",
            "KLean.CS.GolayNumerics",
            "KLean.Geom.OmegaSkeleton",
            "KLean.Modular.SharedDatum",
            "KLean.RH.DiracRigidity"
        ],
        "used_by": ["KLean.Geom.MasterSpine", "KLean.Info.UniformMax", "KLean.Misc.AxiomLedger"],
        "compute": null,
        "seal": {
            "receipt_id": "d017cc7dffff572a7adc3c1d",
            "digest": "ff9469cecfb2bfdf74174682d2499bf3dcc86c0d62e7197d6640fab11f61bd22",
            "sealed_at": "2026-08-10T03:30:24.740384+00:00",
            "time_source": "roughtime_chain"
        },
        "commit": "d2e7d1d"
    }"#;

    #[test]
    fn deserializes_real_api_shape() {
        let cert: Certificate = serde_json::from_str(LIVE_FIXTURE).unwrap();
        assert_eq!(
            cert.fqn,
            "KLean.CS.Golay23HammingBound.golay23_shannon_hamming_bound"
        );
        assert_eq!(cert.verified, Some(true));
        assert_eq!(cert.axiom_level.as_deref(), Some("kernel-standard"));
        assert!(cert.kernel_standard());
        assert_eq!(cert.commit, "d2e7d1d");
        assert!(!cert.quarantined);
        assert_eq!(cert.compute, None);
        assert!(cert.seal.is_some());
        assert_eq!(cert.depends_on.len(), 5);
        assert_eq!(cert.used_by.len(), 3);
        assert_eq!(cert.topics.len(), 4);
        assert_eq!(
            cert.refs,
            vec!["https://doi.org/10.1109/JRPROC.1949.233620".to_string()]
        );
    }

    #[test]
    fn verified_is_none_when_absent_not_false() {
        // 서버가 이 커밋의 .olean 에서 못 찾은 경우 흉내. verified 가 아예 없다.
        let json = r#"{"fqn":"KLean.Some.Unknown","quarantined":false}"#;
        let cert: Certificate = serde_json::from_str(json).unwrap();
        assert_eq!(cert.verified, None, "누락 = None, false 로 뭉개면 안 된다");
        assert!(!cert.kernel_standard());
        assert_eq!(cert.commit, "");
        assert!(cert.refs.is_empty());
    }

    #[test]
    fn compiler_trusted_is_not_kernel_standard() {
        let json = r#"{"fqn":"X.y","axiom_level":"compiler-trusted","quarantined":false}"#;
        let cert: Certificate = serde_json::from_str(json).unwrap();
        assert!(!cert.kernel_standard());
    }

    #[test]
    fn percent_encode_matches_python_quote_safe_empty() {
        // urllib.parse.quote("KLean.CS.Foo.bar", safe='') 와 동일해야 한다 —
        // 점은 unreserved 라 인코딩되지 않는다.
        assert_eq!(
            percent_encode("KLean.CS.Golay23HammingBound.golay23_shannon_hamming_bound"),
            "KLean.CS.Golay23HammingBound.golay23_shannon_hamming_bound"
        );
        assert_eq!(percent_encode("a b"), "a%20b");
        assert_eq!(percent_encode("a/b"), "a%2Fb");
    }
}
