#!/usr/bin/env bash
set -Eeuo pipefail

# Detect a merged TTTPS/K-Lean PR, re-run the local proof gate, and optionally
# invoke explicitly configured catalog/deploy commands. No command is guessed.
# Missing deployment commands are a HOLD, never a false success.

REPO="${TTTPS_PROMOTE_REPO:-Helm-Protocol/kenosian-lean4}"
PR_NUMBER="${TTTPS_PROMOTE_PR:-4}"
KLEAN_DIR="${KLEAN_DIR:-/home/axcpeter/kenosian-lean4}"
KLEAN_FILE="${KLEAN_FILE:-KLean/TTTPS/Core.lean}"
KPP_BASE="${KPP_BASE:-https://kpp.kenosian.com}"
STATE_FILE="${TTTPS_PROMOTE_STATE:-${XDG_STATE_HOME:-$HOME/.local/state}/kenosian/tttps-pr-promoter.json}"
MODE="once"
DRY_RUN=0
INTERVAL="${TTTPS_PROMOTE_INTERVAL:-60}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KLEAN_CATALOG_CMD="${KLEAN_CATALOG_CMD:-$SCRIPT_DIR/tttps-klean-remote-build.sh}"
KPP_REINDEX_CMD="${KPP_REINDEX_CMD:-$SCRIPT_DIR/tttps-kpp-remote-reindex.sh}"

usage() {
  cat <<'EOF'
Usage: tttps-pr-promoter.sh [--once|--watch] [--interval SEC] [--dry-run]

Required for public reindex (not inferred):
  KLEAN_CATALOG_CMD='...'   local catalog generation command
  KPP_REINDEX_CMD='...'      deployment/reindex command for kpp.kenosian.com
EOF
}

while (($#)); do
  case "$1" in
    --once) MODE=once ;;
    --watch) MODE=watch ;;
    --interval) shift; INTERVAL="${1:?missing interval}" ;;
    --dry-run) DRY_RUN=1 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
  shift
done

require_cmd() { command -v "$1" >/dev/null 2>&1 || { echo "HOLD: missing command: $1" >&2; return 1; }; }
mkdir -p "$(dirname "$STATE_FILE")"

check_catalog() {
  local fqn="KLean.TTTPS.invalid_ingress_no_mutation" code
  code="$(curl --max-time 12 -sS -o /tmp/tttps-pr-promoter-catalog.json -w '%{http_code}' "$KPP_BASE/v1/klv/theorem/$fqn" || true)"
  if [[ "$code" == 200 ]] && rg -q '"verified"[[:space:]]*:[[:space:]]*true' /tmp/tttps-pr-promoter-catalog.json; then
    echo "CATALOG_PASS fqn=$fqn"
    return 0
  fi
  echo "CATALOG_HOLD http=$code fqn=$fqn"
  return 1
}

run_once() {
  require_cmd gh || return 2
  require_cmd curl || return 2
  [[ -d "$KLEAN_DIR" ]] || { echo "HOLD: KLEAN_DIR not found: $KLEAN_DIR" >&2; return 2; }

  local state merged sha prior
  state="$(gh pr view "$PR_NUMBER" --repo "$REPO" --json state,mergedAt,mergeCommit,baseRefName,headRefName)" || {
    echo "HOLD: cannot read PR $REPO#$PR_NUMBER" >&2; return 2;
  }
  merged="$(jq -r '.state == "MERGED"' <<<"$state")"
  sha="$(jq -r '.mergeCommit.oid // empty' <<<"$state")"
  if [[ "$merged" != true || -z "$sha" ]]; then
    echo "WAIT: PR not merged: $REPO#$PR_NUMBER"
    return 0
  fi

  prior="$(jq -r '.merge_sha // empty' "$STATE_FILE" 2>/dev/null || true)"
  if [[ "$prior" == "$sha" ]] && [[ "$DRY_RUN" == 0 ]]; then
    check_catalog || true
    return 0
  fi

  echo "MERGED repo=$REPO pr=$PR_NUMBER merge_sha=$sha"
  if [[ "$DRY_RUN" == 1 ]]; then
    echo "DRY_RUN: would verify Lean, then catalog/deploy commands"
    return 0
  fi

  require_cmd lake || return 2
  echo "LEAN_CHECK: $KLEAN_FILE"
  (cd "$KLEAN_DIR" && lake env lean "$KLEAN_FILE")

  export TTTPS_EXPECTED_MERGE_SHA="$sha"
  echo "CATALOG_BUILD: configured command"
  bash -lc "$KLEAN_CATALOG_CMD"

  echo "KPP_REINDEX: configured command"
  bash -lc "$KPP_REINDEX_CMD"

  jq -n --arg repo "$REPO" --argjson pr "$PR_NUMBER" --arg sha "$sha" \
    '{repo:$repo,pr:$pr,merge_sha:$sha,status:"reindex_requested"}' >"$STATE_FILE"
  check_catalog
}

if [[ "$MODE" == once ]]; then
  run_once
  exit $?
fi
while :; do
  run_once || rc=$? || true
  rc="${rc:-0}"
  unset rc
  sleep "$INTERVAL"
done
