"""Kenosian Vault — 수학적 주장이 Lean 4 커널을 통과했는지 O(1) 로 묻는다.

두 갈래가 있고 역할이 다르다.

    조회 (online)    Vault().theorem(fqn)   금고가 이미 검증한 것을 물어본다
    로컬 (filter)    check("proof.lean")    내 증명이 통과하는지 5초에 본다

⛔이 패키지는 논문의 실험을 재현해주지 않는다. 논문이 입각한 **수학적 주장**이
  커널 표준을 통과했는지를 답하고, 그 답을 우리 서버 없이도 확인할 수 있게 한다.

⛔이 패키지는 **얇은 껍질**이다. 계산을 하지 않는다.
    조회   HTTP GET → JSON. 무거운 것(파싱·해시·DAG)은 Rust `kh vault sync` 가
           이미 끝내 Redis 에 얹어놨고, 여기는 그걸 꺼내기만 한다.
    로컬   `lake env lean` 을 부르고 `#print axioms` 출력을 읽는다.
           판정은 **Lean 커널**이 한다. 파이썬은 부르고 읽을 뿐이다.
  파이썬인 이유는 하나뿐이다 — PyPI 에 올리려면 파이썬이어야 한다.
  Rust 로 쓰면 `pip install` 이 안 되고 PyO3 로 하면 1초 설치가 깨진다.
"""

from .client import Certificate, StaleVaultError, Vault, VaultError
from .local import STANDARD_AXIOMS, CheckResult, check

__version__ = "0.1.0"
__all__ = [
    "Vault", "Certificate", "VaultError", "StaleVaultError",
    "check", "CheckResult", "STANDARD_AXIOMS",
    "__version__",
]
