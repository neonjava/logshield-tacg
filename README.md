# LogShield TACG

**Remote showcase and local fallback:** see [docs/REMOTE_DEMO.md](docs/REMOTE_DEMO.md). The VPS demonstration uses three Rust replicas, authenticated log agents, real gateway requests, and a dashboard reachable through an SSH tunnel; the same demo works locally if the VPS is unavailable.

**AI26CY03 — Log-Based Intrusion Detection**

LogShield TACG is a defensive security-monitoring project. It collects system, application, authentication, and gateway logs; connects related events across time and servers; shows the evidence behind an incident; and verifies a local defensive response. Its detection engine and backend are written in Rust. The React dashboard displays results and offers controlled demonstration tools.

> **Status:** The original isolated Docker lab is verified end to end. A second, more realistic multi-server application infrastructure is being integrated. Its Redis/PostgreSQL services, agents, MFA flows, and download/export UI should be treated as **in progress until the Docker integration checks pass**. This README distinguishes verified behavior from that extension.

## The problem

Organizations generate more logs than a person can inspect in time. A single failed login may be harmless, but a series of failures spread across servers, repeated MFA failures, or a completed login after suspicious attempts can indicate intrusion. Per-server thresholds can miss the combined pattern. Security teams need timely alerts that answer **what happened, which records support it, why it is unusual, how severe it is, and whether a response worked**.

## The solution

LogShield normalizes incoming records into typed security events, builds a **Temporal Attack Correlation Graph (TACG)**, and calculates an explicit risk score. Events become nodes. Time-decayed edges link events with a common source, account, host, service, request, or meaningful transition. The graph reconstructs an attack sequence and produces an incident with raw logs, relationships, score contributions, and recommended actions. The score is computed in Rust rather than hidden behind an LLM.

The risk calculation weights event rarity (20), temporal strength (20), entity relationship (15), transition risk (20), cross-host activity (10), and behavior deviation (15), then applies an explained chain bonus. Risk levels are low (0–39), medium (40–69), high (70–84), and critical (85–100). Automatic action also requires sufficient **rule-based evidence strength** and an **approved local response adapter**. The API retains the field name `confidence` for compatibility; it is a score out of 100, **not** a probability that the activity is malicious.

Distributed detection requires a connected, time-decayed path of same-account failures across hosts; a centralized source counter alone cannot trigger that rule. Multi-stage detection enforces failure → success → privilege action → outbound activity in chronological order. A familiar account/source/host history lowers the distributed pattern below automatic containment while retaining an alert. The [small labeled comparison](docs/EVALUATION.md) gives reproducible fixture results and their limits.

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

Automatic collection is the main path. The lab uses a read-only file sensor; the shared-portal infrastructure uses per-server agents and a typed Rust ingestion SDK. The Events page accepts limited UTF-8 `.log`, `.txt`, and `.jsonl` uploads, offers safe downloadable samples, and exports stored records. Manual uploads can create explained incidents but **never authorize automatic containment**. Live agent credentials are generated locally and must not be committed.

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

Start the local lab with:

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

Open `http://127.0.0.1:5173`. The local API is `http://127.0.0.1:3000`. `docker compose down` retains data volumes. `docker compose down -v` erases **this project's** lab and database volumes.

## Current API and demonstrations

The REST API includes `/api/status`, `/api/stats`, `/api/events`, `/api/incidents`, `/api/entities`, `/api/responses`, `/api/logs/upload`, and the fixed `/api/lab/*` scenario controls. `/ws/events` streams live updates. Authenticated agent ingestion and fixed `/api/infra/*` controls are exercised by the Docker integration test.

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

The Docker integration test needs the release binaries and Compose image built first. It exercises shared sessions across replicas, PostgreSQL activity persistence, agent-authenticated log delivery, headline detections, normal-traffic protection, uploaded-log provenance, and verified containment or failure. GitHub Actions runs formatting, Clippy, unit tests, and the frontend build on push; the Docker integration job can be launched manually. The [small labeled comparison](docs/EVALUATION.md) is a rule regression check, not a representative benchmark.

## Known limitations and next steps

The lab uses controlled source labels, fixed dummy credentials, and a polling file sensor. It is designed for a safe demonstration, not arbitrary network traffic. Operator authentication and trustworthy source attribution are required before use with real organizations. The API still loads a bounded recent event set and recomputes correlations after batches; sustained-volume latency is unmeasured. Future production work includes tenant isolation, secret management, durable agent enrollment and rotation handling, representative labeled-data evaluation, calibrated baselines, incremental correlation, and human-reviewed response policy.
