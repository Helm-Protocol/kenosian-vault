# TTTPS K-Lean / Kenosian Vault bridge

Status: preparation record for the OmniVault integration session.

## Boundary

K-Lean is the formal model. Kenosian Vault is the runtime. A Lean theorem is
evidence about the model and is not, by itself, a proof of an arbitrary Rust
implementation. The runtime may claim alignment only after the Rust parser and
gate are checked against the same field offsets, failure states, and test
vectors.

## Current formal evidence

Source: `/home/axcpeter/kenosian-lean4/KLean/TTTPS/Core.lean`

Command:

```text
cd /home/axcpeter/kenosian-lean4
lake env lean KLean/TTTPS/Core.lean
```

The checked model covers deterministic parse selection, fixed 180-octet input,
state preservation on parse failure, invalid-ingress no-mutation, and the
commit delta for valid ingress. The source has no `sorry`; the state-equality
theorems retain their explicit standard `propext` dependency.

TLA+ evidence is in the TTTPS repository:

```text
docs/ietf/formal/TTTPS_Ingress_Gate.tla
docs/ietf/formal/TTTPS_Ingress_Gate.cfg
```

The bounded TLC run completed with exit status 0, 631 generated states, 343
distinct states, and depth 9. Its cryptographic predicates are abstract inputs;
the result is not a cryptographic proof.

## Runtime contract for OmniVault

The runtime integration MUST preserve these boundaries:

1. Read exactly one 180-octet core record before application admission.
2. Reject an invalid length or core predicate without changing application
   state or the commit marker.
3. Perform holder binding and issuer-trust resolution before admission.
4. Invoke confidence and deep-space profiles only as policy/context inputs;
   they do not change the core record layout.
5. Commit application state only after the required predicates return success.

## Remote seal status

The Lean source was checked and sealed through the deployed KVault service. The
service returned receipt `33108706ed730e5296ae1b06` for content hash
`6116b82318d540a1e4e5b694e31978739851f658356330349b9d4289aeb5bae8`; the
receipt verification endpoint returned `verified: true` with
`time_source: roughtime_chain`.

The deployed service currently returns HTTP 404 for the publish route
`POST /v1/klv/submit`. The established repository path is now open as PR
[kenosian-lean4#4](https://github.com/Helm-Protocol/kenosian-lean4/pull/4);
K-Lean PR #4 has since merged, but the deployed Vault catalog still returns HTTP 404
until its catalog index is rebuilt and deployed. This is recorded in `TTTPS_FORMAL_RECEIPT_20260922.json`;
it is not treated as catalog completion.

The Rust implementation must be tested independently for bounds safety,
allocation behavior, byte offsets, and state mutation. The formal model must
not be cited as evidence for those runtime properties until those checks are
recorded.

## Tomorrow's integration boundary

The OmniVault work should add the smallest adapter that maps the Rust parser's
result into the model's states. It should first produce positive and negative
fixed-record vectors, then run the invalid-ingress no-mutation test, and only
then connect the result to the Vault sealing/storage path. No production
service or storage migration is implied by this preparation record.
