//! API 키 보관. `~/.config/kenosian/credentials`, 권한 0600.
//!
//! ★키는 언제나 `SecretString` 안에 있다. `Debug` 로 찍어도, 로그에 실어도
//!   원문이 나오지 않는다 — 노출은 `expose_secret()` 을 부른 그 한 줄에서만 일어난다.

use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::PathBuf;

use secrecy::{ExposeSecret, SecretString};

/// 환경변수로 덮어쓰기. CI 에서 파일 없이 쓰는 길.
pub const ENV_KEY: &str = "KENOSIAN_API_KEY";

#[derive(Debug, thiserror::Error)]
pub enum CredsError {
    #[error("홈 디렉토리를 찾을 수 없다 (HOME 이 비어 있다)")]
    NoHome,

    #[error(
        "API 키가 없다. `kvault login <이메일>` 로 즉시 발급받아라 \
         (승인 없음, 무료 1,000 seal). 또는 {ENV_KEY} 환경변수로 넣어라"
    )]
    Missing,

    #[error("자격증명 파일을 읽을 수 없다: {path} ({source})")]
    Unreadable {
        path: String,
        #[source]
        source: std::io::Error,
    },

    #[error("자격증명 파일에 api_key 줄이 없다: {path}")]
    Malformed { path: String },

    #[error("자격증명을 저장할 수 없다: {path} ({source})")]
    Unwritable {
        path: String,
        #[source]
        source: std::io::Error,
    },
}

impl CredsError {
    pub fn name(&self) -> &'static str {
        match self {
            CredsError::NoHome => "no_home",
            CredsError::Missing => "missing_api_key",
            CredsError::Unreadable { .. } => "credentials_unreadable",
            CredsError::Malformed { .. } => "credentials_malformed",
            CredsError::Unwritable { .. } => "credentials_unwritable",
        }
    }
}

pub fn credentials_path() -> Result<PathBuf, CredsError> {
    if let Some(dir) = std::env::var_os("KENOSIAN_CONFIG_DIR") {
        return Ok(PathBuf::from(dir).join("credentials"));
    }
    let base = match std::env::var_os("XDG_CONFIG_HOME") {
        Some(x) if !x.is_empty() => PathBuf::from(x),
        _ => PathBuf::from(std::env::var_os("HOME").ok_or(CredsError::NoHome)?).join(".config"),
    };
    Ok(base.join("kenosian").join("credentials"))
}

/// 키를 찾는다. 환경변수가 파일보다 앞선다.
pub fn load_key() -> Result<SecretString, CredsError> {
    if let Ok(v) = std::env::var(ENV_KEY) {
        let v = v.trim().to_string();
        if !v.is_empty() {
            tracing::debug!("API 키를 {ENV_KEY} 환경변수에서 읽었다");
            return Ok(SecretString::from(v));
        }
    }

    let path = credentials_path()?;
    if !path.exists() {
        return Err(CredsError::Missing);
    }

    // 권한이 헐거우면 조용히 넘어가지 않는다. 막지는 않되 반드시 말한다.
    if let Ok(md) = std::fs::metadata(&path) {
        let mode = md.permissions().mode() & 0o077;
        if mode != 0 {
            tracing::warn!(
                path = %path.display(),
                "자격증명 파일이 남에게 읽힌다 (mode {:o}). chmod 600 해라",
                md.permissions().mode() & 0o7777
            );
        }
    }

    let text = std::fs::read_to_string(&path)
        .map_err(|e| CredsError::Unreadable { path: path.display().to_string(), source: e })?;

    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((k, v)) = line.split_once('=') {
            if k.trim() == "api_key" {
                let v = v.trim().to_string();
                if !v.is_empty() {
                    return Ok(SecretString::from(v));
                }
            }
        }
    }
    Err(CredsError::Malformed { path: path.display().to_string() })
}

/// 발급받은 키를 0600 으로 저장한다. 디렉토리는 0700 으로 만든다.
pub fn save_key(key: &SecretString, key_id: &str, email: &str) -> Result<PathBuf, CredsError> {
    let path = credentials_path()?;
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(|e| CredsError::Unwritable {
            path: dir.display().to_string(),
            source: e,
        })?;
        let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
    }

    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&path)
        .map_err(|e| CredsError::Unwritable { path: path.display().to_string(), source: e })?;

    // 이미 있던 파일이면 mode() 는 무시되므로 다시 못 박는다.
    let _ = f.set_permissions(std::fs::Permissions::from_mode(0o600));

    let body = format!(
        "# kenosian vault — provenance API key\n\
         # 이 파일은 0600 이다. 커밋하지 마라. 원문 키는 서버가 갖고 있지 않다(sha256 만 보관).\n\
         email = {email}\n\
         key_id = {key_id}\n\
         api_key = {}\n",
        key.expose_secret()
    );
    f.write_all(body.as_bytes())
        .map_err(|e| CredsError::Unwritable { path: path.display().to_string(), source: e })?;

    Ok(path)
}
