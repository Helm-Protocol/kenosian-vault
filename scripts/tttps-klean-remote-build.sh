#!/usr/bin/env bash
set -Eeuo pipefail

PROJECT="${TTTPS_GCP_PROJECT:-gen-lang-client-0808489779}"
INSTANCE="${TTTPS_GCP_INSTANCE:-instance-20260208-045620}"
ZONE="${TTTPS_GCP_ZONE:-us-central1-c}"
REMOTE_REPO="${TTTPS_REMOTE_KLEAN_DIR:-/home/axcpeter/kenosian-lean4}"
MERGE_SHA="${TTTPS_EXPECTED_MERGE_SHA:?promoter must provide the merged commit SHA}"

gcloud compute ssh "$INSTANCE" --project="$PROJECT" --zone="$ZONE" \
  --tunnel-through-iap --command="set -Eeuo pipefail
cd '$REMOTE_REPO'
git fetch origin main
test \"\$(git rev-parse origin/main)\" = '$MERGE_SHA'
test -z \"\$(git status --porcelain | grep -v '^?? ' || true)\"
git switch --detach origin/main
export PATH=/home/axcpeter/.elan/bin:\\$PATH
lake build KLean.TTTPS.Core
test -n \"\$(find .lake/build -type f -path '*KLean/TTTPS/Core.olean' -print -quit)\"
echo REMOTE_LEAN_BUILD_PASS merge_sha=$MERGE_SHA"
