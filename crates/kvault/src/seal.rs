//! ② 봉인 — 파일 바이트의 sha256 만 서버로 보낸다. 원문은 절대 나가지 않는다.
//!
//! ★핵심 규칙: 요청을 보내기 **직전에** 해시를 계산하고, 응답을 받은 **직후에 다시**
//!   계산해 같은지 본다. 다르면 그 사이에 파일이 바뀐 것이므로 영수증을 무효로
//!   표시하고 실패한다. 이것이 "해시 안 바뀐 것만 올라간다" 를 물리적으로 강제하는
//!   자리다 — 다음 차수의 PR 단계도 이 재계산 결과에 매달린다.
//!
//! ⛔조용한 실패 금지. 키가 없어서인지, 네트워크가 죽어서인지, 서버가 거절해서인지를
//!   사용자가 구분할 수 있어야 한다. 실패마다 원인에 이름이 붙는다.

use std::path::{Path, PathBuf};
use std::time::Duration;

use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const DEFAULT_BASE_URL: &str = "https://kpp.kenosian.com";

// ── 서버 스키마. openapi-vault.json 에서 그대로 옮겼다.
//    ⛔필드 이름 하나 틀리면 422 다. 추측하지 말고 스펙을 봐라.

#[derive(Debug, Clone, Serialize)]
pub struct AnchorRequest {
    pub content_hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub theorem_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub external_ref: Option<String>,
    pub require_chain_time: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnchorResponse {
    pub receipt_id: String,
    pub receipt: Option<String>,
    pub content_hash: String,
    pub time: String,
    pub time_source: String,
    pub backdating_p: String,
    pub verify_url: String,
    pub quota: i64,
    pub used: i64,
    pub remaining: i64,
    pub note: String,
}

#[derive(Debug, Clone, Serialize)]
struct KeyRequest<'a> {
    email: &'a str,
    use_case: &'a str,
}

#[derive(Debug, Clone, Deserialize)]
pub struct KeyResponse {
    pub api_key: String,
    pub quota: i64,
    pub used: i64,
    pub key_id: String,
    pub message: String,
}

#[derive(Debug, thiserror::Error)]
pub enum SealError {
    #[error("파일을 읽을 수 없다: {path} ({source})")]
    FileUnreadable {
        path: String,
        #[source]
        source: std::io::Error,
    },

    #[error("{0}")]
    Credentials(#[from] crate::creds::CredsError),

    #[error("서버에 닿지 못했다 ({url}): {detail} — 네트워크나 프록시를 봐라")]
    Unreachable { url: String, detail: String },

    #[error("서버 응답이 {secs}s 안에 오지 않았다 ({url})")]
    Timeout { url: String, secs: u64 },

    #[error("무료 seal 한도를 다 썼다 (402). 키를 새로 발급하거나 유료 한도를 올려라")]
    QuotaExhausted,

    #[error("서버가 키를 모른다 (403). `kvault login <이메일>` 로 다시 발급받아라")]
    UnknownKey,

    #[error("서버가 요청을 거절했다 (422 {error}): {message}")]
    Rejected { error: String, message: String },

    #[error("서버 오류 (HTTP {status}): {body}")]
    ServerError { status: u16, body: String },

    #[error("서버 응답을 읽을 수 없다 (HTTP {status}): {detail}")]
    MalformedResponse { status: u16, detail: String },

    #[error(
        "봉인 도중 파일이 바뀌었다. 영수증은 무효다.\n  \
         전: {before}\n  후: {after}"
    )]
    HashChangedDuringSeal {
        before: String,
        after: String,
        receipt: Box<AnchorResponse>,
    },

    #[error("서버가 다른 해시를 되돌려줬다 (보낸 것 {sent}, 받은 것 {echoed})")]
    DigestMismatch { sent: String, echoed: String },

    #[error("영수증을 저장할 수 없다: {path} ({source})")]
    ReceiptUnwritable {
        path: String,
        #[source]
        source: std::io::Error,
    },
}

impl SealError {
    pub fn name(&self) -> &'static str {
        match self {
            SealError::FileUnreadable { .. } => "file_unreadable",
            SealError::Credentials(e) => e.name(),
            SealError::Unreachable { .. } => "network_unreachable",
            SealError::Timeout { .. } => "network_timeout",
            SealError::QuotaExhausted => "quota_exhausted",
            SealError::UnknownKey => "unknown_key",
            SealError::Rejected { .. } => "server_rejected",
            SealError::ServerError { .. } => "server_error",
            SealError::MalformedResponse { .. } => "malformed_response",
            SealError::HashChangedDuringSeal { .. } => "hash_changed_during_seal",
            SealError::DigestMismatch { .. } => "digest_mismatch",
            SealError::ReceiptUnwritable { .. } => "receipt_unwritable",
        }
    }
}

/// 파일 **바이트**의 sha256 hex.
pub fn sha256_file(path: &Path) -> Result<String, SealError> {
    let bytes = std::fs::read(path)
        .map_err(|e| SealError::FileUnreadable { path: path.display().to_string(), source: e })?;
    let mut h = Sha256::new();
    h.update(&bytes);
    Ok(hex(&h.finalize()))
}

/// `sha256:<hex>` 에서 hex 만 꺼낸다. 접두사가 없으면 그대로 돌려준다.
pub fn bare_digest(s: &str) -> &str {
    match s.strip_prefix("sha256:") {
        Some(rest) => rest,
        None => s,
    }
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// 봉인을 실제로 수행하는 것. 테스트가 가짜를 끼워 넣을 수 있게 트레잇으로 둔다 —
/// 해시 재계산 게이트를 네트워크 없이 실증하려면 이 자리가 필요하다.
pub trait Anchorer {
    fn anchor(&self, req: &AnchorRequest) -> Result<AnchorResponse, SealError>;
}

pub struct HttpAnchorer {
    agent: ureq::Agent,
    base_url: String,
    key: SecretString,
    timeout_secs: u64,
}

impl HttpAnchorer {
    pub fn new(base_url: &str, key: SecretString, timeout: Duration) -> Self {
        let config = ureq::Agent::config_builder()
            .timeout_global(Some(timeout))
            // 4xx 를 예외로 바꾸지 않는다. 본문을 읽어야 이유에 이름을 붙일 수 있다.
            .http_status_as_error(false)
            .user_agent(concat!("kvault/", env!("CARGO_PKG_VERSION")))
            .build();
        HttpAnchorer {
            agent: ureq::Agent::new_with_config(config),
            base_url: base_url.trim_end_matches('/').to_string(),
            key,
            timeout_secs: timeout.as_secs(),
        }
    }
}

impl Anchorer for HttpAnchorer {
    fn anchor(&self, req: &AnchorRequest) -> Result<AnchorResponse, SealError> {
        let url = format!("{}/v1/anchor", self.base_url);

        // ★키는 본문이 아니라 헤더로 보낸다. 본문 구조체에 넣지 않으면
        //   직렬화된 JSON 이 로그나 에러에 실려도 키가 새지 않는다.
        let resp = self
            .agent
            .post(&url)
            .header("X-API-Key", self.key.expose_secret())
            .send_json(req)
            .map_err(|e| transport_error(&url, self.timeout_secs, e))?;

        read_anchor(resp, &url)
    }
}

fn transport_error(url: &str, secs: u64, e: ureq::Error) -> SealError {
    match e {
        ureq::Error::Timeout(_) => SealError::Timeout { url: url.to_string(), secs },
        other => SealError::Unreachable { url: url.to_string(), detail: other.to_string() },
    }
}

fn read_anchor(mut resp: ureq::http::Response<ureq::Body>, url: &str) -> Result<AnchorResponse, SealError> {
    let status = resp.status().as_u16();
    let body = resp
        .body_mut()
        .read_to_string()
        .map_err(|e| SealError::MalformedResponse { status, detail: e.to_string() })?;

    match status {
        200 => serde_json::from_str::<AnchorResponse>(&body)
            .map_err(|e| SealError::MalformedResponse { status, detail: e.to_string() }),
        402 => Err(SealError::QuotaExhausted),
        403 => Err(SealError::UnknownKey),
        422 => {
            let (error, message) = detail_of(&body);
            Err(SealError::Rejected { error, message })
        }
        s if s >= 500 => Err(SealError::ServerError { status: s, body: truncate(&body, 400) }),
        s => Err(SealError::ServerError { status: s, body: format!("{} ({url})", truncate(&body, 400)) }),
    }
}

/// 422 본문은 `{"detail": {"error": ..., "message": ...}}` 또는 FastAPI 기본형이다.
fn detail_of(body: &str) -> (String, String) {
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(body) {
        if let Some(d) = v.get("detail") {
            let error = d.get("error").and_then(|x| x.as_str()).unwrap_or("validation_error");
            let message = d
                .get("message")
                .and_then(|x| x.as_str())
                .map(str::to_string)
                .unwrap_or_else(|| d.to_string());
            return (error.to_string(), message);
        }
    }
    ("validation_error".to_string(), truncate(body, 400))
}

fn truncate(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_string()
    } else {
        s.chars().take(n).collect::<String>() + "…"
    }
}

/// 키 발급. 승인 없음, 무료 1,000 seal. 원문 키는 한 번만 돌아온다.
pub fn mint_key(
    base_url: &str,
    email: &str,
    use_case: &str,
    timeout: Duration,
) -> Result<KeyResponse, SealError> {
    let base = base_url.trim_end_matches('/');
    let url = format!("{base}/v1/keys");
    let config = ureq::Agent::config_builder()
        .timeout_global(Some(timeout))
        .http_status_as_error(false)
        .user_agent(concat!("kvault/", env!("CARGO_PKG_VERSION")))
        .build();
    let agent = ureq::Agent::new_with_config(config);

    let mut resp = agent
        .post(&url)
        .send_json(KeyRequest { email, use_case })
        .map_err(|e| transport_error(&url, timeout.as_secs(), e))?;

    let status = resp.status().as_u16();
    let body = resp
        .body_mut()
        .read_to_string()
        .map_err(|e| SealError::MalformedResponse { status, detail: e.to_string() })?;

    match status {
        200 => serde_json::from_str::<KeyResponse>(&body)
            .map_err(|e| SealError::MalformedResponse { status, detail: e.to_string() }),
        422 => {
            let (error, message) = detail_of(&body);
            Err(SealError::Rejected { error, message })
        }
        s => Err(SealError::ServerError { status: s, body: truncate(&body, 400) }),
    }
}

/// 봉인 성공 산출물.
#[derive(Debug, Clone)]
pub struct Sealed {
    pub content_hash: String,
    pub response: AnchorResponse,
}

/// ★해시 재계산 게이트. 보내기 직전 · 받은 직후 두 번 센다.
pub fn seal_file(
    path: &Path,
    anchorer: &dyn Anchorer,
    theorem_id: Option<String>,
    external_ref: Option<String>,
    require_chain_time: bool,
) -> Result<Sealed, SealError> {
    let before = sha256_file(path)?;
    tracing::debug!(digest = %before, "봉인 직전 해시");

    let req = AnchorRequest {
        content_hash: before.clone(),
        theorem_id,
        external_ref,
        require_chain_time,
    };
    let response = anchorer.anchor(&req)?;

    let after = sha256_file(path)?;
    tracing::debug!(digest = %after, "봉인 직후 재계산");

    if after != before {
        return Err(SealError::HashChangedDuringSeal {
            before,
            after,
            receipt: Box::new(response),
        });
    }
    // ★서버는 다이제스트를 `sha256:<hex>` 로 정규화해 되돌려준다(2026-08-10 실측).
    //   접두사를 벗기고 견준다 — 벗기지 않으면 성공한 봉인을 우리가 실패로 오판한다.
    if !bare_digest(&response.content_hash).eq_ignore_ascii_case(&before) {
        return Err(SealError::DigestMismatch {
            sent: before,
            echoed: response.content_hash,
        });
    }

    Ok(Sealed { content_hash: before, response })
}

/// 파일 옆에 남기는 영수증. 무효 영수증도 남긴다 —
/// seal 은 이미 차감됐고, 무엇이 왜 무효인지가 기록으로 남아야 한다.
#[derive(Debug, Serialize)]
pub struct ReceiptFile {
    pub kvault_version: &'static str,
    pub file: String,
    pub valid: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub void_reason: Option<&'static str>,
    pub content_hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_hash_after: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub axiom_level: Option<&'static str>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub axioms: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub theorems: Vec<String>,
    pub anchor: AnchorResponse,
}

pub fn receipt_path(lean: &Path) -> PathBuf {
    let mut s = lean.as_os_str().to_os_string();
    s.push(".receipt.json");
    PathBuf::from(s)
}

pub fn write_receipt(lean: &Path, r: &ReceiptFile) -> Result<PathBuf, SealError> {
    let out = receipt_path(lean);
    let json = serde_json::to_string_pretty(r)
        .map_err(|e| SealError::ReceiptUnwritable { path: out.display().to_string(), source: std::io::Error::other(e) })?;
    std::fs::write(&out, json.as_bytes() )
        .map_err(|e| SealError::ReceiptUnwritable { path: out.display().to_string(), source: e })?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_is_lowercase_and_padded() {
        assert_eq!(hex(&[0u8, 15, 255]), "000fff");
    }

    #[test]
    fn known_sha256() {
        let dir = std::env::temp_dir().join(format!("kvault-hex-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let f = dir.join("abc.txt");
        if std::fs::write(&f, b"abc").is_ok() {
            let d = sha256_file(&f);
            assert_eq!(
                d.ok().as_deref(),
                Some("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn detail_of_reads_server_shape() {
        let body = r#"{"detail":{"error":"missing_api_key","message":"Supply your key ..."}}"#;
        let (e, m) = detail_of(body);
        assert_eq!(e, "missing_api_key");
        assert!(m.starts_with("Supply your key"));
    }

    #[test]
    fn bare_digest_strips_server_prefix() {
        // 2026-08-10 실측: /v1/anchor 는 `sha256:<hex>` 로 정규화해 되돌려준다.
        assert_eq!(bare_digest("sha256:abc123"), "abc123");
        assert_eq!(bare_digest("abc123"), "abc123");
    }

    #[test]
    fn error_names_are_stable() {
        assert_eq!(SealError::QuotaExhausted.name(), "quota_exhausted");
        assert_eq!(SealError::UnknownKey.name(), "unknown_key");
    }
}
