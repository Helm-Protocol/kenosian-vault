//! `kvault` — 기여자가 자기 기계에서 Lean 증명을 검증하고, 통과분만 TTTPS 로 봉인한다.
//!
//! ★설계 의도가 코드보다 먼저다: 검증(`lake`)은 **사용자 기계**에서 돈다. 그래서
//!   우리 서버 부하가 0이고, 우리 서버가 꺼져 있어도 검증은 계속 된다. 서버가 받는
//!   것은 봉인 요청의 해시 한 번뿐이고, 원문은 절대 나가지 않는다.
//!
//! - `check`  — ① 로컬 커널 검증. 서버를 부르지 않는다.
//! - `submit` — ① → ② 연속. kernel-standard 통과분만 봉인한다.
//! - `submit --publish` — ① → ② → ③. 봉인된 그 바이트를 저장소에 PR 로 올린다.
//!   ★③ 에서도 서버는 Lean 을 돌리지 않는다. 해시 대조뿐이고, 병합은 사람이 한다.
//! - `login`  — 키 발급(승인 없음, 무료 1,000 seal).

pub mod check;
pub mod comments;
pub mod creds;
pub mod publish;
pub mod seal;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
