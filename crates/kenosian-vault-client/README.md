# kenosian-vault

Ask whether a mathematical claim passed the Lean 4 kernel — in one call, verifiable without our server.

```rust
use kenosian_vault::Vault;

let v = Vault::new();
let c = v.verify("KLean.Atoms.Bio.BiologicalAgeAtom.weighted_sum_nonneg")?;
println!("{:?} {:?}", c.verified, c.axiom_level); // Some(true) Some("kernel-standard")
```

Thin blocking HTTP client for `https://kpp.kenosian.com/v1/klv/*`, built on `ureq`
(no forced `tokio` runtime — same choice as the sibling `kvault` CLI in this repo).
Mirrors the canonical Python client (`src/kenosian_vault/client.py`) field-for-field.

## `verified` is `Option<bool>`, not `bool`

`None` means "not in this commit's `.olean`" — i.e. unknown, not `false`. Collapsing
that to a plain bool would be selling certainty we don't have.

## API

- `Vault::new()` / `Vault::with_base(base)` / `Vault::with_expect_commit(commit)` / `Vault::with_options(base, timeout, expect_commit)`
- `.theorem(fqn) -> Result<Certificate, VaultError>`
- `.verify(fqn)` — alias for `.theorem()`. Same HTTP GET, not a live re-verification: the
  kernel already ran in CI, this is an O(1) lookup of that result.
- `.stats() -> Result<serde_json::Value, VaultError>`
- `.impact(module) -> Result<Vec<String>, VaultError>` — reverse dependents
- `.served_commit() -> Result<String, VaultError>`

Pin an audit to a specific commit with `expect_commit`; a mismatched
`X-KLV-Commit-Hash` on the response returns `VaultError::Stale`.

## Feature flags

None yet. v0.1.0 ships sync-only. An `async` feature (via `reqwest`) may follow if
there's real demand — it will stay off by default.

## License

Apache-2.0
