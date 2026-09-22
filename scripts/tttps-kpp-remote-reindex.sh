#!/usr/bin/env bash
set -Eeuo pipefail

PROJECT="${TTTPS_GCP_PROJECT:-gen-lang-client-0808489779}"
INSTANCE="${TTTPS_GCP_INSTANCE:-instance-20260208-045620}"
ZONE="${TTTPS_GCP_ZONE:-us-central1-c}"
REMOTE_REPO="${TTTPS_REMOTE_KLEAN_DIR:-/home/axcpeter/kenosian-lean4}"
SYNC="${TTTPS_REMOTE_SYNC:-/home/axcpeter/kenosian-repo/kpp/api/app/engines/redis_vault_sync.py}"
FQN="KLean.TTTPS.invalid_ingress_no_mutation"
MERGE_SHA="${TTTPS_EXPECTED_MERGE_SHA:?promoter must provide the merged commit SHA}"

gcloud compute ssh "$INSTANCE" --project="$PROJECT" --zone="$ZONE" \
  --tunnel-through-iap --command="set -Eeuo pipefail
cd '$REMOTE_REPO'
test -n \"\$(find .lake/build -type f -path '*KLean/TTTPS/Core.olean' -print -quit)\"
python3 '$SYNC' >/tmp/tttps-kpp-reindex.log
curl --fail --max-time 15 -sS http://127.0.0.1:8901/v1/klv/theorem/$FQN >/tmp/tttps-kpp-theorem.json
grep -q '\"verified\":true' /tmp/tttps-kpp-theorem.json
grep -q \"\\\"commit\\\":\\\"${MERGE_SHA:0:10}\" /tmp/tttps-kpp-theorem.json
echo REMOTE_KPP_REINDEX_PASS fqn=$FQN"
