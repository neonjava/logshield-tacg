# LogShield TACG

**AI26CY03 — Log-Based Intrusion Detection**

LogShield TACG is a defensive security-monitoring project. It collects system, application, authentication, and gateway logs; connects related events across time and servers; shows the evidence behind an incident; and verifies a local defensive response. Its detection engine and backend are written in Rust. The React dashboard displays results and offers controlled demonstration tools.

> **Status:** The original isolated Docker lab is verified end to end. A second, more realistic multi-server application infrastructure is being integrated. Its Redis/PostgreSQL services, agents, MFA flows, and download/export UI should be treated as **in progress until the Docker integration checks pass**. This README distinguishes verified behavior from that extension.

## The problem

Organizations generate more logs than a person can inspect in time. A single failed login may be harmless, but a series of failures spread across servers, repeated MFA failures, or a completed login after suspicious attempts can indicate intrusion. Per-server thresholds can miss the combined pattern. Security teams need timely alerts that answer **what happened, which records support it, why it is unusual, how severe it is, and whether a response worked**.

## The solution

LogShield normalizes incoming records into typed security events, builds a **Temporal Attack Correlation Graph (TACG)**, and calculates an explicit risk score. Events become nodes. Time-decayed edges link events with a common source, account, host, service, request, or meaningful transition. The graph reconstructs an attack sequence and produces an incident with raw logs, relationships, score contributions, and recommended actions. The score is computed in Rust rather than hidden behind an LLM.

The risk calculation weights event rarity (20), temporal strength (20), entity relationship (15), transition risk (20), cross-host activity (10), and behavior deviation (15), then applies an explained chain bonus. Risk levels are low (0–39), medium (40–69), high (70–84), and critical (85–100). Automatic action also requires sufficient confidence and an **approved local response adapter**.

## Two local demonstration environments

### Verified security lab

The existing lab has a Rust client, Rust gateway, and three small Rust services: `app-a`, `app-b`, and `app-c`. Requests go through the gateway. Each app writes a real JSON log. A read-only Rust sensor follows the files and sends events to TACG. The dashboard persists evidence in SQLite. In the strongest test, one source produces two failures on A, two on B, and one on C. Every server stays below a five-failure threshold, but LogShield detects the five related failures across three hosts. For an eligible incident, the gateway applies a local denylist entry. A real retry must receive HTTP 403 for the incident to become `CONTAINED`; otherwise it becomes `RESPONSE_FAILED`.

```text
controlled client → Rust gateway → app-a / app-b / app-c
                                      ↓ real JSON logs
                        Rust file sensor → normalizer → TACG
                                                      ↓
                         SQLite evidence ← incident + risk
                                                      ↓
                        gateway block → retry → verify HTTP result
```

The Lab page also provides normal traffic, a multi-stage sequence, forced response failure, and links to three sample browser pages. These are **client views for fixed Docker targets**, not internet-facing applications.

### Multi-server application extension — in progress

The new local infrastructure is designed to show how a company could attach LogShield to a real application stack. Three Rust servers run a shared portal behind round-robin gateway routing. A user completes a password **and MFA** login once, then uses one Redis-backed session across the servers. Each server also exposes a distinct protected activity: operations, reports, or inventory. PostgreSQL holds the dummy user and activity records; Redis holds expiring challenges and sessions. Each server writes its own log, and a read-only Rust agent submits those logs through an authenticated ingestion API. A Rust SDK supports applications that prefer direct event submission. LogShield's SQLite remains separate from application data.

```text
browser/terminal → fixed local API → Rust gateway → round-robin portal replicas
                                                ├─ infra-a: operations
                                                ├─ infra-b: reports
                                                └─ infra-c: inventory
                                                            ↓
                       PostgreSQL app data + Redis sessions/challenges
                                                            ↓
                        per-server logs → Rust agents → LogShield API
                                                            ↓
                               TACG → SQLite incidents → SOC dashboard
```

This extension will demonstrate three primary detections: **brute-force password attempts**, a **suspicious completed login** after failures or from a historically new source, and **repeated failed MFA checks**. A change of replica alone is normal load-balancer behavior and must not be flagged. A password alone is not a completed login when MFA is required.

## Log sources and provenance

Automatic collection is the main path. The verified lab uses a read-only file sensor; the new extension uses per-server agents and a typed Rust ingestion SDK. The Events page already accepts limited UTF-8 `.log`, `.txt`, and `.jsonl` uploads. The planned Logs & Events view will add downloadable safe samples and an export of current records. Manual uploads are for parsing and investigation demos: they can create explained incidents but **must never authorize automatic containment**. Live agent credentials are generated locally and must not be committed.

The ingestion path validates input size and format, never executes log contents, and stores evidence with source provenance. No uploaded record should be trusted to claim the identity of an authenticated agent.

## Architecture and boundaries

- **Rust core:** normalization, baseline, time decay, graph construction, attack-chain reconstruction, risk, incidents, and response decisions.
- **Rust API:** REST, WebSocket, ingestion, file sensor, SQLite persistence, and approved response coordination.
- **Rust gateway:** fixed local routes, network request logs, denylist enforcement, and actual HTTP verification.
- **Rust lab and infrastructure services:** controlled request generation and applications that produce genuine logs.
- **React/Vite:** SOC views, raw evidence, score breakdown, response proof, and lab controls. It does not perform security detection.

Docker networks isolate the lab. The API is published only on localhost; the gateway, application servers, Redis, and PostgreSQL have no host-facing ports. The project does **not** scan external systems, exploit vulnerabilities, or modify the host firewall. Outside the lab, LogShield should alert by default and use an explicitly configured, authorized adapter for any defensive action. This is a local mentor demo and integration template, **not a production-ready multi-tenant service**.

## Running the verified lab and the extension

Prerequisites: stable Rust, Cargo, Docker with Compose, Node 22+, and npm. The Dockerfile packages host-built Fedora 44 x86-64 Rust binaries; another host platform needs compatible Linux builds or a Dockerfile adaptation.

After the extension compiles, the intended startup is:

```bash
cd /path/to/logshield
cargo run -p logshield-ingest --bin logshield-agent -- init-demo  # creates ignored local .env once
cargo build --release --workspace
docker compose build
docker compose up -d
cd frontend
npm install
npm run dev
```

Open `http://127.0.0.1:5173`. The local API is `http://127.0.0.1:3000`. The infrastructure extension is still being validated; follow the test results before using it for a presentation. `docker compose down` retains data volumes. `docker compose down -v` erases **this project's** lab and database volumes.

## Current API and demonstrations

The verified REST API includes `/api/status`, `/api/stats`, `/api/events`, `/api/incidents`, `/api/entities`, `/api/responses`, `/api/logs/upload`, and the fixed `/api/lab/*` scenario controls. `/ws/events` streams live updates. The infrastructure extension adds authenticated event ingestion and fixed `/api/infra/*` controls; those routes are not considered verified until integration tests pass.

For the original two-minute demonstration, see [docs/DEMO.md](docs/DEMO.md). For design and judge explanations, see [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md), [docs/TACG.md](docs/TACG.md), [docs/REAL_WORLD_PROBLEM.md](docs/REAL_WORLD_PROBLEM.md), and [docs/PITCH.md](docs/PITCH.md).

## Testing

```bash
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo build --workspace
cargo test -p logshield-api --test lab_e2e -- --ignored
cd frontend && npm run build
```

The Docker integration test needs the release binaries and Compose image built first. The completed infrastructure work must additionally prove shared sessions across replicas, PostgreSQL activity persistence, agent-authenticated log delivery, the three headline detections, normal-traffic protection, uploaded-log provenance, and verified containment or failure.

## Known limitations and next steps

The original lab uses controlled source labels, fixed dummy credentials, and a polling file sensor. It is designed for a safe demonstration, not arbitrary network traffic. Its gateway identity and API access model need authenticated deployment controls before use with real organizations. The new Redis/PostgreSQL/agent infrastructure is under implementation and must not be presented as tested until its end-to-end gates pass. Future production work includes tenant isolation, secret management, authenticated operators, durable agent enrollment and rotation handling, calibrated baselines, and human-reviewed response policy.
