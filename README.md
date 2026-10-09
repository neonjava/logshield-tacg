# LogShield TACG

**AI26CY03 — Log-Based Intrusion Detection**

LogShield is a local defensive monitoring system. Three controlled Rust applications receive real HTTP requests through a Rust gateway and write structured authentication logs. A read-only Rust sensor follows those files, normalizes each line, and sends events to the existing Temporal Attack Correlation Graph (TACG). The graph correlates source, account, host, service, time and event transitions. Incidents include real log evidence and an explicit risk breakdown. When a high-confidence lab incident reaches risk 85, the Rust response engine applies a real denylist entry at the lab gateway and asks the lab client to retry. **Only a matching HTTP 403 marks the incident `CONTAINED`.**

The system never scans or attacks outside its fixed local lab. It never changes the host firewall. The only allowed targets are `app-a`, `app-b` and `app-c` on isolated Docker networks.

## Why it matters

Five failures from one source can be spread as 2 on A, 2 on B and 1 on C. Each host stays below a five-failure rule, yet the same identity and account across three hosts within a short interval forms an actionable pattern. TACG reconstructs that pattern and exposes its evidence. See [the real-world problem](docs/REAL_WORLD_PROBLEM.md) and [algorithm](docs/TACG.md).

## Architecture

```text
fixed Rust lab client → Rust gateway → Rust apps → JSON log files
                                               ↓
read-only Rust sensor → normalizer → TACG → incident → SQLite
                                         ↓
                    response engine → gateway block → lab retry
                                                       ↓
                                    HTTP 403 → CONTAINED
                                    HTTP 401 → RESPONSE_FAILED
```

All security processing, services, database access, API and WebSocket are Rust. React only presents evidence. Rust provides memory safety, strong types, predictable performance, Tokio concurrency and low runtime overhead for a future long-running agent. See [architecture](docs/ARCHITECTURE.md).

### Timeline: current workflow

| Step | What happens now |
|---|---|
| 1. Request | A Lab button, one of the three sample pages, or a fixed-target terminal command asks the Rust lab client to send a request. |
| 2. Gateway | The Rust gateway checks its local denylist, then either forwards the request to app-a/b/c or returns HTTP 403. |
| 3. Real log | The selected Rust app handles the request and appends a structured JSON record to its shared log file. |
| 4. Detection | The read-only Rust sensor follows new log lines. Normalization creates typed events; TACG links them across source, user, host, time and event transitions. |
| 5. Incident | The Rust risk engine creates an explainable incident and persists events, graph edges, scores and evidence in SQLite. REST and WebSocket update the React dashboard. |
| 6. Response | For an eligible high-confidence incident, the response engine requests a 60-second block from the lab gateway. |
| 7. Verification | The lab client retries. A matching HTTP 403 proves containment; if the request still reaches the app, the incident becomes `RESPONSE_FAILED`. |

### Current infrastructure

| Component | Runs as | Purpose |
|---|---|---|
| SOC dashboard and three sample pages | React/Vite on host `127.0.0.1:5173` | Operator view and controlled manual requests; no detection logic |
| `logshield-api` | Rust Axum Docker service, exposed only at `127.0.0.1:3000` | REST, WebSocket, file sensor, TACG, incidents, response and SQLite |
| `attacker-lab` | Rust Docker service | Sends only predefined requests to the gateway and performs verification retries |
| `logshield-gateway` | Rust Docker service | Fixed app routing, local denylist and actual HTTP 403 enforcement |
| `app-a`, `app-b`, `app-c` | Three Rust Docker services | Dummy login and safe lab operations; each writes its own JSON log |
| Storage | Docker named volumes | Shared app logs, SQLite state and persisted gateway block records |

The three app pages are browser **client views**, while the actual applications run as isolated Docker services. Only the dashboard and API have localhost host ports. Docker's internal networks carry lab traffic; this setup never modifies the host firewall or contacts arbitrary targets.

## Requirements and startup

The supplied fast Docker image packages **host-built Fedora 44 x86-64 Rust binaries** into a Fedora 44 runtime. This matches the current local development machine. Install stable Rust, Docker with the Compose plugin, Node 22+ and npm. For another host OS, build inside a compatible Linux environment or adapt the Dockerfile.

```bash
cd /home/neonjava/logshield
cargo build --release -p logshield-api -p logshield-lab
docker compose build
docker compose up -d
```

In a second terminal:

```bash
cd /home/neonjava/logshield/frontend
npm install
npm run dev
```

Open **http://127.0.0.1:5173**. The API is published only on `127.0.0.1:3000`; gateway, apps and client have no host ports. Lab traffic uses three `internal: true` networks. A separate ingress bridge connects only the API to the localhost dashboard. Application logs and SQLite live in named volumes. To stop: `docker compose down`. `docker compose down` retains named volumes. Use the Lab page's **Clear lab data** to reset incidents, events and the gateway denylist while retaining raw log files; the sensor skips old lines after reset.

## Pages

- **Overview:** gateway, sensor, TACG, database and service health; event rate, last event, open incidents and verified responses.
- **Incidents:** real event timeline, clickable graph entities, per-host threshold comparison, reasons, exact score contributions and gateway proof trail.
- **Events:** normalized event table. Click a row for the raw line, normalized fields, graph links and incident membership.
- **Entities:** source, destination, host, account and service inventory from persisted logs.
- **Responses:** gateway action and verification ledger.
- **Lab:** fixed normal, distributed and multi-stage tests, forced response failure, and lab reset.

## Demo paths

- **Normal:** three valid dummy logins; no critical incident.
- **Distributed:** five invalid logins as 2/2/1 across A/B/C from `attacker-lab`, username `demo`. TACG detects the cross-host attack, risk exceeds 85, and the gateway blocks the source for 60 seconds. The client retries and receives HTTP 403.
- **Multi-stage:** two failed logins, successful dummy login, intentional lab admin operation and local outbound-style operation. These are safe endpoints, not vulnerabilities.
- **Force response failure:** gateway refuses the block (HTTP 503); the client retries and receives HTTP 401 from the app, proving the request got through. Incident remains `RESPONSE_FAILED` and calls for human intervention.

The demo client never inserts an event directly into TACG. Its requests pass through the gateway, app log, and Rust sensor. For a hands-on showcase, open the **Lab** page and its three sample app links (`/lab/app-a`, `/lab/app-b`, `/lab/app-c`). The pages display actual gateway results for manual logins and safe lab operations. The fixed-target terminal commands and exact two-minute script are in [docs/DEMO.md](docs/DEMO.md).

## API

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/status` | Operational health and event rate |
| GET | `/api/stats` | Persisted counts |
| GET | `/api/events` | Recent normalized events |
| POST | `/api/events` | Accept a normalized event from a trusted local integration |
| POST | `/api/logs/upload` | Import UTF-8 `.log`, `.txt`, `.jsonl` up to 1 MiB |
| GET | `/api/entities` | Observed entities |
| GET | `/api/incidents`, `/api/incidents/{id}` | Incident queue and evidence |
| GET | `/api/incidents/{id}/response`, `/api/responses` | Response and HTTP verification |
| POST | `/api/lab/run/{normal,distributed,multistage}` | Ask the fixed lab client to send real requests |
| POST | `/api/lab/attempt` | One fixed-target request to app-a, app-b, or app-c through the lab gateway |
| POST | `/api/lab/force-failure` | Lab-only `{ "enabled": true }` |
| POST | `/api/lab/clear` | Reset lab records and gateway block |
| WS | `/ws/events` | Live event and incident notifications |

The gateway's `/internal/block` receives a fixed `attacker-lab` source, incident ID, reason and duration. It maintains a persisted denylist; the API stores a separate audit record.

## Quality gates

```bash
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo build --workspace
cd frontend && npm run build
```

The Docker integration test boots the prebuilt lab and proves normal behavior, distributed correlation, each per-host count below five, the gateway block, a real HTTP 403, SQLite persistence, and the forced-failure HTTP 401 path:

```bash
cd /home/neonjava/logshield
cargo test -p logshield-api --test lab_e2e -- --ignored
```

Build the release binaries and Compose image before this explicit integration test. It clears **only LogShield lab data**. Run it when no other process owns localhost port 3000.

## Security and limitations

The lab endpoints and gateway accept only fixed app names and paths. Logs are never executed; SQL uses bound parameters; upload size is capped; React escapes text. The API and internal gateway endpoints have no production authentication because this is an isolated local lab. Do not publish the gateway or API beyond localhost or reuse this setup on untrusted networks. The gateway trusts the controlled client's `x-lab-source` label; a production gateway must derive identity from authenticated network or mTLS context. TACG currently groups primarily by source and uses a simple baseline and bounded recent-event window. The file sensor polls rather than using kernel notifications and does not yet persist offsets across restarts; duplicate event IDs are ignored by SQLite. Docker packaging is Fedora 44 x86-64 specific. Production work includes authenticated ingestion, robust log formats, rotation-aware offsets, calibrated scores, durable agents, multi-tenant identity resolution and human-reviewed response policy.
