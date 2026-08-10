//! 해시 재계산 게이트를 네트워크 없이 실증한다.
//!
//! 봉인 요청을 보내는 **도중에** 파일이 바뀌는 상황을 가짜 Anchorer 로 인위적으로
//! 재현한다. "됐다" 는 서술이 아니라 before/after 두 다이제스트와 오류 이름을
//! 출력으로 남긴다 — `cargo test -- --nocapture` 로 보면 된다.

use std::path::{Path, PathBuf};

use kvault::seal::{AnchorRequest, AnchorResponse, Anchorer, SealError};

fn canned(content_hash: &str) -> AnchorResponse {
    AnchorResponse {
        receipt_id: "rcpt_fake_0001".into(),
        receipt: Some("fake-signature".into()),
        content_hash: content_hash.to_string(),
        time: "2026-08-10T00:00:00+00:00".into(),
        time_source: "roughtime_chain".into(),
        backdating_p: "2^-128".into(),
        verify_url: "https://kpp.kenosian.com/v1/verify?receipt_id=rcpt_fake_0001".into(),
        quota: 1000,
        used: 1,
        remaining: 999,
        note: "fake".into(),
    }
}

/// 서버가 응답하는 사이에 누군가 파일을 고쳤다.
struct MutatingAnchorer {
    path: PathBuf,
    new_bytes: &'static [u8],
}

impl Anchorer for MutatingAnchorer {
    fn anchor(&self, req: &AnchorRequest) -> Result<AnchorResponse, SealError> {
        // ★이 자리가 "요청 보낸 뒤 ~ 응답 받기 전" 이다.
        std::fs::write(&self.path, self.new_bytes).map_err(|e| SealError::FileUnreadable {
            path: self.path.display().to_string(),
            source: e,
        })?;
        Ok(canned(&req.content_hash))
    }
}

/// 아무 일도 없었던 정상 경로.
struct QuietAnchorer;

impl Anchorer for QuietAnchorer {
    fn anchor(&self, req: &AnchorRequest) -> Result<AnchorResponse, SealError> {
        Ok(canned(&req.content_hash))
    }
}

/// 서버가 엉뚱한 해시를 되돌려준 경우.
struct LyingAnchorer;

impl Anchorer for LyingAnchorer {
    fn anchor(&self, _req: &AnchorRequest) -> Result<AnchorResponse, SealError> {
        Ok(canned(&"0".repeat(64)))
    }
}

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("kvault-test-{}-{}", std::process::id(), name));
    let _ = std::fs::create_dir_all(&dir);
    dir.join("Proof.lean")
}

fn cleanup(p: &Path) {
    if let Some(d) = p.parent() {
        let _ = std::fs::remove_dir_all(d);
    }
}

#[test]
fn hash_changed_during_seal_is_caught_and_receipt_is_void() {
    let path = scratch("mutating");
    std::fs::write(&path, b"theorem a : True := trivial\n").expect_err_free();

    let before = kvault::seal::sha256_file(&path).unwrap_or_default();

    let anchorer = MutatingAnchorer { path: path.clone(), new_bytes: b"theorem a : True := by sorry\n" };
    let out = kvault::seal::seal_file(&path, &anchorer, None, None, false);

    match out {
        Err(SealError::HashChangedDuringSeal { before: b, after: a, receipt }) => {
            println!("[gate] error_name  = {}", SealError::HashChangedDuringSeal {
                before: b.clone(),
                after: a.clone(),
                receipt: receipt.clone(),
            }
            .name());
            println!("[gate] before      = {b}");
            println!("[gate] after       = {a}");
            println!("[gate] receipt_id  = {} (무효로 표시된다)", receipt.receipt_id);
            assert_eq!(b, before, "봉인 직전 해시는 원본 그대로여야 한다");
            assert_ne!(a, b, "바뀐 파일이면 두 해시가 달라야 한다");
        }
        Err(other) => panic!("다른 오류가 났다: [{}] {other}", other.name()),
        Ok(_) => panic!("게이트가 통과시켰다 — 이건 잡혀야 한다"),
    }
    cleanup(&path);
}

#[test]
fn unchanged_file_seals_cleanly() {
    let path = scratch("quiet");
    std::fs::write(&path, b"theorem a : True := trivial\n").expect_err_free();

    let sealed = kvault::seal::seal_file(&path, &QuietAnchorer, None, None, false);
    match sealed {
        Ok(s) => {
            println!("[gate] sealed digest = {}", s.content_hash);
            println!("[gate] receipt_id    = {}", s.response.receipt_id);
            assert_eq!(s.content_hash, s.response.content_hash);
        }
        Err(e) => panic!("바뀌지 않은 파일이 막혔다: [{}] {e}", e.name()),
    }
    cleanup(&path);
}

#[test]
fn server_echoing_a_different_digest_is_rejected() {
    let path = scratch("lying");
    std::fs::write(&path, b"theorem a : True := trivial\n").expect_err_free();

    match kvault::seal::seal_file(&path, &LyingAnchorer, None, None, false) {
        Err(e @ SealError::DigestMismatch { .. }) => {
            println!("[gate] error_name = {}", e.name());
            println!("[gate] {e}");
        }
        Err(other) => panic!("다른 오류가 났다: [{}] {other}", other.name()),
        Ok(_) => panic!("서버가 다른 해시를 줬는데 통과시켰다"),
    }
    cleanup(&path);
}

/// 테스트 준비 단계에서 `expect(` 를 쓰지 않으려고 두는 작은 도우미.
trait ErrFree {
    fn expect_err_free(self);
}

impl<E: std::fmt::Display> ErrFree for Result<(), E> {
    fn expect_err_free(self) {
        if let Err(e) = self {
            panic!("테스트 준비 실패: {e}");
        }
    }
}
