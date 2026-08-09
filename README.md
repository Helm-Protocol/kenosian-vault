# kenosian-vault

Ask whether a mathematical claim passed the Lean 4 kernel — in one call.

```bash
pip install kenosian-vault
```

No Lean toolchain is bundled. No dependencies. The install is a second.

## Query the vault

```python
from kenosian_vault import Vault

v = Vault()
c = v.theorem("KLean.Atoms.Bio.BiologicalAgeAtom.weighted_sum_nonneg")

c.verified          # True
c.axiom_level       # 'kernel-standard'
c.kernel_standard   # True
c.olean_sha256      # '0ccb1c02...'
c.commit            # 'fc0a692'  — the vault commit that answered
```

`verified` is `True` or `None`, never `False`. `None` means the compiled artifact
is not present at that commit — that is *unknown*, not *false*. We do not sell a
`true` we cannot back.

## Pin a commit when you audit

A vault that moves under you gives different answers to the same question.

```python
v = Vault(expect_commit="fc0a692")
v.theorem(...)      # raises StaleVaultError if the server has moved on
```

Every response carries `X-KLV-Commit-Hash`, so you can reconcile against a static
manifest without trusting the live server.

## Check your own proof locally

```python
from kenosian_vault import check

r = check("my_proof.lean")
if r.ok:
    print(r.axiom_level, r.axioms)
else:
    print(r.reason)
```

This calls the `lake` you already have. If Lean is not installed it says so
rather than pretending.

**This is a filter, not a gatekeeper.** The result can be forged — editing this
file is enough. Client-side verification cannot be a basis for trust. What you
get is a failure known in five seconds, which is where its value is: bad
submissions never become pull requests.

Trust comes from the CI that re-runs the kernel after you submit.

## What this is not

It does not reproduce a paper's experiments. It answers whether the **mathematical
claims** a paper rests on passed the kernel, and lets you confirm that answer
without our server.

## What counts as passing

`kernel-standard` means the proof depends only on `propext`, `Classical.choice`,
and `Quot.sound`. If `native_decide` is involved, the level drops to
`compiler-trusted` — the compiler is then in the trusted base, and we say so
rather than hiding it.

A proof whose axioms include `sorryAx` did not close. That is reported as broken,
not as verified.

---

Apache-2.0
