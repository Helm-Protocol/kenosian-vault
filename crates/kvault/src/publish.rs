//! ③ 등재 — 봉인된 파일을 저장소에 PR 로 올린다.
//!
//! ★서버는 Lean 을 돌리지 않는다. 커널은 이미 이 기계에서 돌았고(`kvault check`),
//!   봉인이 그때의 다이제스트를 못 박았다. 서버가 하는 일은 대조 하나뿐이다 —
//!   지금 보낸 바이트의 sha256 이 영수증의 content_hash 와 같은가.
//!
//! ★그래서 보내기 직전에 여기서 한 번 더 센다. 봉인 이후 파일이 바뀌었으면
//!   서버에 물어보기 전에 우리 쪽에서 먼저 멈춘다 — 같은 규율이 `seal.rs` 에도 있고,
//!   여기서 다시 도는 이유는 봉인과 등재 사이에도 시간이 흐르기 때문이다.
//!
//! ⛔조용한 실패 금지. 왜 막혔는지가 언제나 이름으로 남는다.

use std::path::Path;
use std::time::Duration;

use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::seal::bare_digest;

#[derive(Debug, Clone, Serialize)]
struct SubmitRequest<'a> {
    receipt_id: &'a str,
    path: &'a str,
    content: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    axiom_level: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    note: Option<&'a str>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SubmitResponse {
    pub pr_url: String,
    pub branch: String,
    pub path: String,
    pub content_hash: String,
    pub receipt_id: String,
    pub sealed_at: Option<String>,
    pub message: String,
}

#[derive(Debug, thiserror::Error)]
pub enum PublishError {
    #[error("파일을 읽을 수 없다: {path} ({source})")]
    FileUnreadable {
        path: String,
        #[source]
        source: std::io::Error,
    },

    #[error(
        "파일이 UTF-8 이 아니다: {path}. 등재는 원문을 텍스트로 실어 보내므로 \
         UTF-8 로 저장해야 한다."
    )]
    NotUtf8 { path: String },

    #[error(
        "봉인 이후 파일이 바뀌었다. 등재하지 않았다.\n  \
         봉인된 것: {sealed}\n  지금 파일: {now}\n  \
         `kvault submit` 을 지금 파일에 다시 돌려라."
    )]
    ChangedSinceSeal { sealed: String, now: String },

    #[error(
        "저장소 안에서의 경로를 정할 수 없다: {path}. \
         경로에 `KLean/` 이 없다 — `--path KLean/...` 로 직접 지정해라."
    )]
    PathUndetermined { path: String },

    #[error("서버에 닿지 못했다 ({url}): {detail}")]
    Unreachable { url: String, detail: String },

    #[error("서버 응답이 {secs}s 안에 오지 않았다 ({url})")]
    Timeout { url: String, secs: u64 },

    /// 서버가 이름 붙여 거절한 것. 이름을 그대로 들고 나간다 —
    /// 우리가 다시 지어 붙이면 호출자가 구분하던 것을 잃는다.
    #[error("서버가 등재를 거절했다 (HTTP {status} {error}): {message}")]
    Refused { status: u16, error: String, message: String },

    #[error("서버 응답을 읽을 수 없다 (HTTP {status}): {detail}")]
    MalformedResponse { status: u16, detail: String },
}

impl PublishError {
    pub fn name(&self) -> &str {
        match self {
            PublishError::FileUnreadable { .. } => "file_unreadable",
            PublishError::NotUtf8 { .. } => "not_utf8",
            PublishError::ChangedSinceSeal { .. } => "changed_since_seal",
            PublishError::PathUndetermined { .. } => "publish_path_undetermined",
            PublishError::Unreachable { .. } => "network_unreachable",
            PublishError::Timeout { .. } => "network_timeout",
            // 서버가 붙인 이름 그대로 (receipt_not_found · hash_mismatch ·
            // path_rejected · already_exists · branch_exists · rate_limited ·
            // github_unconfigured · github_error).
            PublishError::Refused { error, .. } => error,
            PublishError::MalformedResponse { .. } => "malformed_response",
        }
    }
}

/// 저장소 안에서의 경로. `.../kenosian-lean4/KLean/Atoms/X.lean` → `KLean/Atoms/X.lean`.
///
/// 추측하지 않는다 — `KLean/` 이라는 확실한 표식이 있을 때만 자른다.
/// 없으면 사용자에게 물어본다(에러). 잘못 찍은 경로는 남의 저장소에 파일을 만든다.
pub fn repo_path(file: &Path) -> Option<String> {
    let s = file.to_string_lossy().replace('\\', "/");
    let idx = s.find("KLean/")?;
    let rel = &s[idx..];
    if rel.ends_with(".lean") {
        Some(rel.to_string())
    } else {
        None
    }
}

fn sha256_bytes(b: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(b);
    h.finalize().iter().map(|x| format!("{x:02x}")).collect()
}

/// 등재. ★보낼 바이트를 한 번만 읽고, 그 바이트로 해시를 세고, 그 바이트를 보낸다 —
/// 읽기와 보내기 사이에 파일을 다시 만지지 않는 것이 대조를 성립시킨다.
#[allow(clippy::too_many_arguments)]
pub fn publish(
    file: &Path,
    repo_rel_path: &str,
    receipt_id: &str,
    sealed_hash: &str,
    axiom_level: Option<&str>,
    note: Option<&str>,
    base_url: &str,
    key: &SecretString,
    timeout: Duration,
) -> Result<SubmitResponse, PublishError> {
    let bytes = std::fs::read(file)
        .map_err(|e| PublishError::FileUnreadable { path: file.display().to_string(), source: e })?;

    // ★봉인 이후 바뀌었는지 여기서 먼저 본다. 서버도 같은 것을 보지만,
    //   틀린 것을 보내고 거절당하는 것과 애초에 보내지 않는 것은 다르다.
    let now = sha256_bytes(&bytes);
    if !now.eq_ignore_ascii_case(bare_digest(sealed_hash)) {
        return Err(PublishError::ChangedSinceSeal {
            sealed: bare_digest(sealed_hash).to_string(),
            now,
        });
    }

    // 서버는 본문을 텍스트로 받아 UTF-8 로 다시 인코딩해 해시한다. 그 왕복이
    // 바이트를 보존하지 못하면 대조가 성립하지 않으므로, 여기서 미리 확인한다.
    let text = String::from_utf8(bytes.clone())
        .map_err(|_| PublishError::NotUtf8 { path: file.display().to_string() })?;
    if text.as_bytes() != bytes.as_slice() {
        return Err(PublishError::NotUtf8 { path: file.display().to_string() });
    }

    let url = format!("{}/v1/klv/submit", base_url.trim_end_matches('/'));
    let config = ureq::Agent::config_builder()
        .timeout_global(Some(timeout))
        .http_status_as_error(false)
        .user_agent(concat!("kvault/", env!("CARGO_PKG_VERSION")))
        .build();
    let agent = ureq::Agent::new_with_config(config);

    let req = SubmitRequest {
        receipt_id,
        path: repo_rel_path,
        content: &text,
        axiom_level,
        note,
    };

    // ★키는 헤더로만. 본문 구조체에 없으면 직렬화된 JSON 이 로그에 실려도 새지 않는다.
    let mut resp = agent
        .post(&url)
        .header("X-API-Key", key.expose_secret())
        .send_json(&req)
        .map_err(|e| match e {
            ureq::Error::Timeout(_) => {
                PublishError::Timeout { url: url.clone(), secs: timeout.as_secs() }
            }
            other => PublishError::Unreachable { url: url.clone(), detail: other.to_string() },
        })?;

    let status = resp.status().as_u16();
    let body = resp
        .body_mut()
        .read_to_string()
        .map_err(|e| PublishError::MalformedResponse { status, detail: e.to_string() })?;

    if status == 200 {
        return serde_json::from_str::<SubmitResponse>(&body)
            .map_err(|e| PublishError::MalformedResponse { status, detail: e.to_string() });
    }

    let (error, message) = named_detail(&body);
    Err(PublishError::Refused { status, error, message })
}

/// `{"detail": {"error": ..., "message": ...}}` 에서 이름과 사유를 꺼낸다.
fn named_detail(body: &str) -> (String, String) {
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(body) {
        if let Some(d) = v.get("detail") {
            let error = d.get("error").and_then(|x| x.as_str()).unwrap_or("server_rejected");
            let message = d
                .get("message")
                .and_then(|x| x.as_str())
                .map(str::to_string)
                .unwrap_or_else(|| d.to_string());
            return (error.to_string(), message);
        }
    }
    ("server_rejected".to_string(), body.chars().take(400).collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn repo_path_cuts_at_klean() {
        assert_eq!(
            repo_path(&PathBuf::from("/home/x/kenosian-lean4/KLean/Atoms/Bio/A.lean")).as_deref(),
            Some("KLean/Atoms/Bio/A.lean")
        );
    }

    #[test]
    fn repo_path_refuses_to_guess() {
        // KLean 표식이 없으면 지어내지 않는다 — 사용자가 --path 로 말해야 한다.
        assert_eq!(repo_path(&PathBuf::from("/tmp/A.lean")), None);
        assert_eq!(repo_path(&PathBuf::from("/x/KLean/A.txt")), None);
    }

    #[test]
    fn sha256_matches_known_vector() {
        assert_eq!(
            sha256_bytes(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn named_detail_keeps_the_servers_name() {
        let (e, m) = named_detail(r#"{"detail":{"error":"hash_mismatch","message":"no"}}"#);
        assert_eq!(e, "hash_mismatch");
        assert_eq!(m, "no");
    }
}
