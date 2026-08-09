"""Kenosian Vault 조회 클라이언트 — 정리가 커널을 통과했는지 물어본다.

    from kenosian_vault import Vault
    v = Vault()
    c = v.theorem("KLean.Atoms.Bio.BiologicalAgeAtom.weighted_sum_nonneg")
    print(c.verified, c.axiom_level)      # True  kernel-standard

★Lean 툴체인을 번들하지 않는다. 이건 HTTP 클라이언트이고 `pip install` 이 1초다.
  로컬에서 직접 증명을 검증하려면 `kenosian_vault.local` 을 쓴다 — 그건 이미 설치된
  lake/lean 을 부르고, 없으면 없다고 말한다.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any

__all__ = ["Vault", "Certificate", "VaultError", "StaleVaultError"]

DEFAULT_BASE = "https://kpp.kenosian.com"
UA = "kenosian-vault-python"


class VaultError(RuntimeError):
    """조회 실패. ⛔이유를 삼키지 않는다 — 조용한 강등이 제일 나쁘다."""


class StaleVaultError(VaultError):
    """서빙 커밋이 기대한 커밋과 다르다. 감사 중이라면 여기서 멈춰야 한다."""


@dataclass(frozen=True)
class Certificate:
    """정리 하나의 검증서.

    ⛔`verified` 는 True/False 가 아니라 **True/None** 이다.
      `.olean` 이 그 커밋에 없으면 "모른다"이지 "거짓"이 아니다.
      이 구분을 없애면 근거 없이 true 를 파는 것과 같아진다(2026-08-08 규칙).
    """

    fqn: str
    verified: bool | None
    axiom_level: str | None
    olean_sha256: str | None
    module: str | None
    path: str | None
    claim: str | None
    quarantined: bool
    commit: str

    @property
    def kernel_standard(self) -> bool:
        """표준 공리만 쓰는가. `native_decide` 가 섞이면 compiler-trusted 로 강등된다."""
        return self.axiom_level == "kernel-standard"

    @classmethod
    def from_json(cls, d: dict[str, Any]) -> "Certificate":
        return cls(
            fqn=d["fqn"],
            verified=d.get("verified"),
            axiom_level=d.get("axiom_level"),
            olean_sha256=d.get("olean_sha256"),
            module=d.get("module"),
            path=d.get("path"),
            claim=d.get("claim"),
            quarantined=bool(d.get("quarantined", False)),
            commit=d.get("commit", ""),
        )


class Vault:
    """`kpp.kenosian.com/v1/klv/*` 를 부르는 얇은 클라이언트.

    expect_commit 을 주면 서빙이 그 커밋이 아닐 때 StaleVaultError 를 던진다.
    감사자가 특정 시점을 검증할 때 쓴다 — 서버가 그새 앞서가면 조용히 다른 답을 받게 되므로.
    """

    def __init__(self, base: str = DEFAULT_BASE, timeout: float = 10.0,
                 expect_commit: str | None = None) -> None:
        self.base = base.rstrip("/")
        self.timeout = timeout
        self.expect_commit = expect_commit

    # ── 내부 ────────────────────────────────────────────────────────────
    def _get(self, path: str) -> tuple[dict[str, Any], str]:
        url = f"{self.base}{path}"
        req = urllib.request.Request(
            url, headers={"User-Agent": UA, "Accept": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                served = resp.headers.get("X-KLV-Commit-Hash", "")
                body = json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            if e.code == 404:
                raise VaultError(f"금고에 없다: {path}") from e
            raise VaultError(f"HTTP {e.code} — {url}") from e
        except urllib.error.URLError as e:
            raise VaultError(f"연결 실패 {url}: {e.reason}") from e
        except json.JSONDecodeError as e:
            raise VaultError(f"JSON 아님 {url}: {e}") from e

        if self.expect_commit and served and served != self.expect_commit:
            raise StaleVaultError(
                f"서빙 커밋 {served} != 기대 {self.expect_commit}. "
                "금고가 앞서갔다 — 같은 시점을 보려면 manifest 를 쓰거나 expect_commit 을 갱신해라."
            )
        return body, served

    # ── 공개 API ────────────────────────────────────────────────────────
    def theorem(self, fqn: str) -> Certificate:
        """정리 하나의 검증서. 없으면 VaultError."""
        body, _ = self._get(f"/v1/klv/theorem/{urllib.parse.quote(fqn, safe='')}")
        return Certificate.from_json(body)

    def stats(self) -> dict[str, Any]:
        """금고 집계와 서빙 커밋."""
        body, _ = self._get("/v1/klv/stats")
        return body

    def impact(self, module: str) -> list[str]:
        """이 모듈이 바뀌면 다시 봐야 하는 모듈들 (역방향 DAG).

        빈 목록은 "잎 모듈"이라는 뜻이지 "없다"는 뜻이 아니다 — 없으면 VaultError 가 난다.
        """
        body, _ = self._get(f"/v1/klv/impact/{urllib.parse.quote(module, safe='')}")
        return list(body.get("dependents", []))

    def served_commit(self) -> str:
        """지금 서빙 중인 금고 커밋."""
        return str(self.stats().get("commit", ""))
