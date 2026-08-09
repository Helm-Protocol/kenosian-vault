"""로컬 검증 — 기여자 머신에서 증명이 커널을 통과하는지 먼저 본다.

    from kenosian_vault import check
    r = check("my_proof.lean")
    if r.ok:  print(r.axioms)          # ['propext', 'Classical.choice', 'Quot.sound']
    else:     print(r.reason)

★이건 **문지기가 아니라 필터**다.
  결과는 위조할 수 있다(이 파일을 고치면 그만이다). 클라이언트 사이드 검증은
  원리적으로 신뢰의 근거가 못 된다. 신뢰는 PR 을 받은 뒤 우리 CI 가 준다.
  여기서 얻는 것은 **5초 만에 아는 실패**다 — 그리고 그게 실무에서 제일 크다.
  로컬에서 걸러지면 쓰레기 PR 이 애초에 안 와서 CI 부하가 급감한다.

★Lean 을 번들하지 않는다. 이미 설치된 `lake` 를 부르고, 없으면 없다고 말한다.
  Lean 연구자는 이미 갖고 있고, 없는 사람은 조회(Vault)만 쓰면 된다.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

__all__ = ["check", "CheckResult", "STANDARD_AXIOMS"]

# Lean 4 커널 표준 공리. 이 셋만 쓰면 kernel-standard.
STANDARD_AXIOMS = frozenset({"propext", "Classical.choice", "Quot.sound"})

_RE_AXIOMS = re.compile(r"'([^']+)'\s+depends on axioms:\s*\[([^\]]*)\]")
_RE_NOAX = re.compile(r"'([^']+)'\s+does not depend on any axioms")


def _strip_comments(src: str) -> str:
    """블록주석 깊이를 세어 코드만 남긴다.

    ⛔`/-.*?-/` 정규식을 쓰면 안 된다. Lean 블록주석은 **중첩된다** —
      2026-08-08 에 그 정규식이 문서 안 코드펜스의 `sorry` 예시를 코드로 세어
      금고 전체를 오염됐다고 오판했다. 2026-08-09 에는 간이 grep 이 279파일에서
      헤더 주석의 "ZERO sorry" 문구를 세어 345건으로 부풀었다(정본 0).
    """
    out: list[str] = []
    depth = 0
    i = 0
    n = len(src)
    while i < n:
        if src.startswith("/-", i):
            depth += 1
            i += 2
            continue
        if src.startswith("-/", i) and depth:
            depth -= 1
            i += 2
            continue
        if depth == 0 and src.startswith("--", i):
            j = src.find("\n", i)
            i = n if j < 0 else j
            continue
        if depth == 0:
            out.append(src[i])
        i += 1
    return "".join(out)


@dataclass(frozen=True)
class CheckResult:
    path: str
    ok: bool
    reason: str = ""
    sorry_count: int = 0
    axiom_keyword_count: int = 0
    axioms: list[str] = field(default_factory=list)
    axiom_level: str | None = None
    stdout: str = ""

    @property
    def kernel_standard(self) -> bool:
        return self.axiom_level == "kernel-standard"


def check(path: str | Path, project: str | Path | None = None,
          timeout: float = 300.0) -> CheckResult:
    """`.lean` 파일 하나를 로컬 커널로 검증한다.

    project 는 `lakefile` 이 있는 디렉토리. 생략하면 파일에서 위로 찾아 올라간다.
    """
    p = Path(path).resolve()
    if not p.exists():
        return CheckResult(str(p), False, f"파일이 없다: {p}")

    src = p.read_text(encoding="utf-8", errors="ignore")
    body = _strip_comments(src)
    n_sorry = len(re.findall(r"\bsorry\b", body))
    n_axiom = len(re.findall(r"(?m)^\s*axiom\s+", body))
    if n_sorry or n_axiom:
        return CheckResult(
            str(p), False,
            f"소스에 sorry {n_sorry}건 · axiom 선언 {n_axiom}건 — 커널을 부르기 전에 걸린다",
            sorry_count=n_sorry, axiom_keyword_count=n_axiom)

    if shutil.which("lake") is None:
        return CheckResult(
            str(p), False,
            "lake 가 없다. Lean 4 툴체인이 필요하다 (elan 으로 설치). "
            "로컬 검증 없이 금고 조회만 하려면 kenosian_vault.Vault 를 써라")

    root = Path(project).resolve() if project else None
    if root is None:
        for anc in [p.parent, *p.parents]:
            if (anc / "lakefile.lean").exists() or (anc / "lakefile.toml").exists():
                root = anc
                break
    if root is None:
        return CheckResult(str(p), False, "lakefile 을 못 찾았다 — project= 로 지정해라")

    try:
        rel = p.relative_to(root)
    except ValueError:
        rel = p

    try:
        proc = subprocess.run(
            ["lake", "env", "lean", str(rel)],
            cwd=str(root), capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return CheckResult(str(p), False, f"시간초과 {timeout}s — 증명이 갇혔을 수 있다")
    except OSError as e:
        return CheckResult(str(p), False, f"lake 실행 실패: {e}")

    out = (proc.stdout or "") + (proc.stderr or "")
    if proc.returncode != 0:
        first = next((l for l in out.splitlines() if "error" in l), "")
        return CheckResult(str(p), False,
                           f"커널이 거부했다 (exit {proc.returncode}): {first[:200]}", stdout=out)

    # `#print axioms` 출력 수집. ⛔없으면 통과로 치지 않는다 —
    #   축을 안 찍으면 무엇에 의존하는지 모르는 것이고, 모르는 것은 통과가 아니다.
    axioms: set[str] = set()
    seen = False
    for m in _RE_AXIOMS.finditer(out):
        seen = True
        axioms.update(a.strip() for a in m.group(2).split(",") if a.strip())
    if _RE_NOAX.search(out):
        seen = True
    if not seen:
        return CheckResult(
            str(p), False,
            "`#print axioms <정리이름>` 이 없다. 무엇에 의존하는지 찍어라 — "
            "모르는 것은 통과가 아니다", stdout=out)

    extra = axioms - STANDARD_AXIOMS
    if "sorryAx" in extra:
        return CheckResult(str(p), False,
                           "축에 sorryAx 가 있다 — 증명이 닫히지 않았다",
                           axioms=sorted(axioms), axiom_level="broken", stdout=out)
    level = "kernel-standard" if not extra else "compiler-trusted"
    return CheckResult(str(p), True, "", axioms=sorted(axioms),
                       axiom_level=level, stdout=out)
