"""Kenosian Vault — 수학적 주장이 Lean 4 커널을 통과했는지 O(1) 로 묻는다.

두 갈래가 있고 역할이 다르다.

    조회 (online)    Vault().theorem(fqn)   금고가 이미 검증한 것을 물어본다
    로컬 (filter)    check("proof.lean")    내 증명이 통과하는지 5초에 본다

⛔이 패키지는 논문의 실험을 재현해주지 않는다. 논문이 입각한 **수학적 주장**이
  커널 표준을 통과했는지를 답하고, 그 답을 우리 서버 없이도 확인할 수 있게 한다.
"""

from .client import Certificate, StaleVaultError, Vault, VaultError
from .local import STANDARD_AXIOMS, CheckResult, check

__version__ = "0.1.0"
__all__ = [
    "Vault", "Certificate", "VaultError", "StaleVaultError",
    "check", "CheckResult", "STANDARD_AXIOMS",
    "__version__",
]
