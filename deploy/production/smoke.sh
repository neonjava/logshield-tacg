#!/usr/bin/env bash
# Disposable localhost deployment test. Refuses to touch an existing private stack.
set -euo pipefail
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo_dir=$(cd -- "$script_dir/../.." && pwd)
cd "$repo_dir"
if [[ -e "$script_dir/.env" || -e "$script_dir/secrets" ]]; then
    echo 'refusing to replace existing private credentials' >&2
    exit 1
fi
if docker compose -p logshield-private ps -q | grep -q .; then
    echo 'refusing to touch an existing private stack' >&2
    exit 1
fi
compose=(docker compose --env-file "$script_dir/.env" -f "$script_dir/compose.yml")
cleanup() {
    "${compose[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
    rm -rf -- "$script_dir/secrets" "$script_dir/.env" "$script_dir/smoke-backup.db"
}
trap cleanup EXIT
umask 077
mkdir -p "$script_dir/secrets"
operator=$(openssl rand -hex 32)
viewer=$(openssl rand -hex 32)
agent=$(openssl rand -hex 32)
printf 'LOGSHIELD_OPERATOR_TOKEN=%s\nLOGSHIELD_VIEWER_TOKEN=%s\nLOGSHIELD_INGEST_TOKENS=\x27{"smoke-agent":"%s"}\x27\nLOGSHIELD_PROXY_UID=%s:%s\n' \
    "$operator" "$viewer" "$agent" "$(id -u)" "$(id -g)" > "$script_dir/.env"
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj /CN=localhost \
    -addext 'subjectAltName=DNS:localhost,IP:127.0.0.1' \
    -keyout "$script_dir/secrets/tls.key" -out "$script_dir/secrets/tls.crt" >/dev/null 2>&1
printf 'viewer:%s\n' "$(openssl passwd -apr1 'local-smoke-only')" > "$script_dir/secrets/htpasswd"
cargo build --release -p logshield-api
(cd frontend && npm ci && npm run build)
"${compose[@]}" build
"${compose[@]}" up -d
for _ in {1..60}; do
    if curl --cacert "$script_dir/secrets/tls.crt" -fsS https://localhost:8443/api/health >/dev/null; then break; fi
    sleep 2
done
tls=(curl --cacert "$script_dir/secrets/tls.crt" -s -o /dev/null -w '%{http_code}')
[[ $("${tls[@]}" https://localhost:8443/) == 401 ]]
[[ $("${tls[@]}" -u viewer:local-smoke-only https://localhost:8443/) == 200 ]]
curl --cacert "$script_dir/secrets/tls.crt" -fsS -u viewer:local-smoke-only https://localhost:8443/ |
    grep -q 'assets/index-'
[[ $("${tls[@]}" -u viewer:local-smoke-only https://localhost:8443/api/events) == 200 ]]
python3 - "$script_dir/secrets/tls.crt" <<'PY'
import base64,socket,ssl,sys
context=ssl.create_default_context(cafile=sys.argv[1])
with socket.create_connection(('127.0.0.1',8443),timeout=5) as raw:
 with context.wrap_socket(raw,server_hostname='localhost') as conn:
  auth=base64.b64encode(b'viewer:local-smoke-only').decode()
  conn.sendall(('GET /ws/events HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\nAuthorization: Basic '+auth+'\r\n\r\n').encode())
  assert b'101 Switching Protocols' in conn.recv(512)
PY
[[ $("${tls[@]}" -X POST -H 'Content-Type: application/json' -d '{"events":[]}' https://localhost:8443/api/ingest/events) == 401 ]]
[[ $(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:3001/api/events) == 401 ]]
[[ $(curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $viewer" -X POST http://127.0.0.1:3001/api/lab/clear) == 401 ]]
[[ $(curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $operator" -X POST http://127.0.0.1:3001/api/lab/clear) == 503 ]]
event_id=$(python3 -c 'import uuid;print(uuid.uuid4())')
payload=$(printf '{"events":[{"id":"%s","event_type":"web_request","source_ip":"smoke-client","destination_ip":null,"hostname":"claimed-host","username":null,"service":"web","port":null,"action":"GET /","result":"success","severity_hint":null,"raw_message":"private smoke"}]}' "$event_id")
[[ $("${tls[@]}" -X POST -H "Authorization: Bearer $agent" -H 'Content-Type: application/json' -d "$payload" https://localhost:8443/api/ingest/events) == 200 ]]
check_event() {
    curl --cacert "$script_dir/secrets/tls.crt" -fsS -u viewer:local-smoke-only https://localhost:8443/api/events |
        python3 -c 'import json,sys; assert sys.argv[1] in {event["id"] for event in json.load(sys.stdin)}' "$event_id"
}
check_event
"$script_dir/backup.sh" "$script_dir/smoke-backup.db"
[[ -s "$script_dir/smoke-backup.db" ]]
marker_id=$(python3 -c 'import uuid;print(uuid.uuid4())')
marker_payload=${payload/$event_id/$marker_id}
[[ $("${tls[@]}" -X POST -H "Authorization: Bearer $agent" -H 'Content-Type: application/json' -d "$marker_payload" https://localhost:8443/api/ingest/events) == 200 ]]
"${compose[@]}" restart api
check_event
"$script_dir/restore.sh" "$script_dir/smoke-backup.db"
check_event
curl --cacert "$script_dir/secrets/tls.crt" -fsS -u viewer:local-smoke-only https://localhost:8443/api/events |
    python3 -c 'import json,sys; assert sys.argv[1] not in {event["id"] for event in json.load(sys.stdin)}' "$marker_id"
echo 'private TLS, authentication, ingestion, restart, and backup/restore smoke checks passed'
