# TTTPS local PR promoter

`scripts/tttps-pr-promoter.sh` watches a merged K-Lean PR and runs the local
Lean gate before any catalog or deployment command. It does not infer a
catalog builder or a server deployment path.

## One-shot check

```bash
TTTPS_PROMOTE_PR=4 \
  ./scripts/tttps-pr-promoter.sh --once
```

Expected current result: local Lean verification succeeds, then the script
returns `HOLD` because no catalog-builder or public deployment command is
configured. A live theorem lookup returning HTTP 404 is never treated as
success.

## Enable the final two steps explicitly

```bash
export KLEAN_CATALOG_CMD='the command that builds the deployed catalog'
export KPP_REINDEX_CMD='the command or SSH deployment hook that rebuilds kpp.kenosian.com'
./scripts/tttps-pr-promoter.sh --watch --interval 60
```

The watcher records the last processed merge SHA under
`$XDG_STATE_HOME/kenosian/tttps-pr-promoter.json` (or
`~/.local/state/...`). It is intentionally fail-closed: without a real
catalog and deployment target it cannot claim that the public 404 was fixed.
