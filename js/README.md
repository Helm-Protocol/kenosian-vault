# @kenosian/vault

Ask whether a mathematical claim passed the Lean 4 kernel — in one call.

```bash
npm install @kenosian/vault
```

No Lean toolchain is bundled. No dependencies. Uses native `fetch` only —
works unmodified on Node 18+, Cloudflare Workers, Vercel Edge, Deno, and
in the browser.

## Query the vault

```ts
import { Vault } from "@kenosian/vault";

const v = new Vault();
const c = await v.theorem("KLean.Atoms.Bio.BiologicalAgeAtom.weighted_sum_nonneg");

c.verified          // true
c.axiom_level       // 'kernel-standard'
c.kernelStandard    // true
c.olean_sha256      // '0ccb1c02...'
c.commit            // 'fc0a692'  — the vault commit that answered
```

`verified` is `true` or `null`, never `false`. `null` means the compiled
artifact is not present at that commit — that is *unknown*, not *false*. We
do not sell a `true` we cannot back.

`verify(fqn)` is an alias for `theorem(fqn)`. The name reads like live
re-verification but is not — it's a single O(1) HTTP GET against a result
the kernel already checked in CI, not code execution on your request.

## Pin a commit when you audit

A vault that moves under you gives different answers to the same question.

```ts
const v = new Vault({ expectCommit: "fc0a692" });
await v.theorem(/* ... */); // throws StaleVaultError if the server has moved on
```

Every response carries `X-KLV-Commit-Hash`, so you can reconcile against a
static manifest without trusting the live server.

## API

- `new Vault(options?)` — `options.base` (default `https://kpp.kenosian.com`),
  `options.timeoutMs` (default `10000`), `options.expectCommit`.
- `vault.theorem(fqn: string): Promise<Certificate>`
- `vault.verify(fqn: string): Promise<Certificate>` — alias for `theorem`.
- `vault.stats(): Promise<Record<string, unknown>>`
- `vault.impact(module: string): Promise<string[]>` — reverse dependents.
- `vault.servedCommit(): Promise<string>`

Errors: `VaultError` on 404 / other HTTP errors / network failure / bad JSON.
`StaleVaultError extends VaultError` when the served commit doesn't match
`expectCommit`.
