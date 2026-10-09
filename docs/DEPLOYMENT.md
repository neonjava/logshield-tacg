# Private self-hosted deployment

LogShield remains an **integration beta**. `deploy/production/compose.yml` is a separate non-lab deployment path, tested locally with disposable credentials and a self-signed certificate. It is not a public-internet configuration.

## Prepare a private Linux host

Install Docker Compose, Rust, Node/npm, OpenSSL, and `htpasswd`. Build the binaries and UI from the repository root:

```bash
cargo build --release --workspace
cd frontend && npm ci && npm run build && cd ..
mkdir -p deploy/production/secrets
cp deploy/production/.env.example deploy/production/.env
```

Set three **different** random tokens in `.env`; `openssl rand -hex 32` generates each. `LOGSHIELD_INGEST_TOKENS` is a JSON map from agent name to its own token. Set `LOGSHIELD_PROXY_UID` to the UID:GID that owns the certificate files (for example, output of `id -u` and `id -g`). Do not commit `.env` or `secrets/`.

Provide a certificate valid for the private hostname in `secrets/tls.crt` and `secrets/tls.key`. For a disposable localhost test only, generate a one-day self-signed certificate:

```bash
openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
  -subj /CN=localhost -addext 'subjectAltName=DNS:localhost,IP:127.0.0.1' \
  -keyout deploy/production/secrets/tls.key -out deploy/production/secrets/tls.crt
htpasswd -cB deploy/production/secrets/htpasswd viewer
chmod 600 deploy/production/.env deploy/production/secrets/tls.key deploy/production/secrets/htpasswd
```

The proxy process runs under `LOGSHIELD_PROXY_UID` and needs read access to those files. On SELinux hosts, Compose relabels the three secret mounts for the container. TLS terminates at Nginx; a browser must pass HTTP Basic authentication. The proxy replaces browser `Authorization` with the viewer token for read-only API and WebSocket routes. Ingest routes preserve each agent's bearer token and have a request-rate limit. Never put the operator token in frontend JavaScript or a URL.

```bash
docker compose --env-file deploy/production/.env -f deploy/production/compose.yml build
docker compose --env-file deploy/production/.env -f deploy/production/compose.yml up -d
```

The dashboard is `https://127.0.0.1:8443/`; the operator API is bound separately to **localhost only** at `http://127.0.0.1:3001`. Use an SSH tunnel for remote operator access. The API has no publicly bound port. `LAB_MODE=false` disables attack controls and automatic containment. Agents send to `https://<private-host>:8443/api/ingest/events` with their source token and a trusted TLS certificate. The application-reported client IP remains unverified metadata.

## Baseline approval

Authenticated agent successes enter a durable quarantine only when their event timestamps are within 30 days and not in the future. The operator must independently review the source before approving. Three distinct, incident-free successful event IDs, one hour of quarantine, and a ten-minute event boundary are required. Send a POST to the localhost operator API with the operator bearer token:

```json
{"username":"alice","source_ip":"192.0.2.9","hostname":"my-app","reviewed_benign":true}
```

Endpoint: `/api/baseline/approve`. Approved snapshots persist in SQLite and are used on later batches, including after restart. A successful login alone never promotes itself. Late discovery of a compromised approved account currently requires manual remediation; there is no automatic revocation of a poisoned snapshot.

## Backup, restore, and upgrades

```bash
deploy/production/backup.sh /secure/backup/logshield.db
deploy/production/restore.sh /secure/backup/logshield.db
```

The backup uses SQLite `VACUUM INTO`, producing a consistent snapshot while the API runs. The restore script copies a validated backup, stops the API, retains the previous database as `/state/pre-restore.db`, replaces the database, and restarts the API. Test restores on disposable data before relying on them. Keep backups encrypted and access restricted; they contain raw security evidence. For upgrades, take a backup, build the new image, recreate the API, verify health and sample evidence, then restore the backup if rollback is required. Never run `docker compose down -v` against real data.

## Operating limits

This configuration was exercised locally with TLS, dashboard auth, read-only viewer access, authenticated ingestion, WebSocket upgrade, restart persistence, disabled lab controls, and one backup/restore drill. It does not establish secure internet exposure or production capacity. The API still correlates up to 2,000 recent events after candidate batches. Source IP attribution depends on the integrating application; there is no mTLS, per-user sessions, high-availability failover, or independently measured field false-positive rate. Non-lab response adapters and automatic mitigation remain disabled.
