//! 라이브 서버에 대고 `verify()` 를 부르는 최소 예제.
//!
//!     cargo run --example verify
//!
//! `KLean.CS.Golay23HammingBound.golay23_shannon_hamming_bound` 는 실제로 존재하고
//! kernel-standard 로 봉인된 정리다 — 이 예제는 재검증이 아니라 이미 CI 에서
//! 통과한 판정을 O(1) 로 조회하는 것을 보여준다.

use kenosian_vault::Vault;

const FQN: &str = "KLean.CS.Golay23HammingBound.golay23_shannon_hamming_bound";

fn main() {
    let v = Vault::new();
    match v.verify(FQN) {
        Ok(c) => {
            println!("fqn:            {}", c.fqn);
            println!("verified:       {:?}", c.verified);
            println!("axiom_level:    {:?}", c.axiom_level);
            println!("kernel_standard: {}", c.kernel_standard());
            println!("quarantined:    {}", c.quarantined);
            println!("module:         {:?}", c.module);
            println!("commit:         {}", c.commit);
            println!("depends_on:     {:?}", c.depends_on);
            println!("used_by:        {:?}", c.used_by);
            println!();
            println!("full certificate:\n{c:#?}");
        }
        Err(e) => {
            eprintln!("verify failed: {e}");
            std::process::exit(1);
        }
    }
}
