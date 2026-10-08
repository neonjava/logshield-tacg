# Architecture

## Trust and network boundary

Compose creates three isolated internal networks: `edge` joins the fixed client to the gateway; `backend` joins the gateway to three apps; `control` joins the API to gateway and client. An `ingress` bridge attaches only the API so Docker can publish its host port, bound to `127.0.0.1:3000`. The React Vite server runs on localhost separately. The lab does not accept arbitrary target URLs.

## Data plane

1. The Rust client sends a fixed `POST /app-{a,b,c}/login` through the Rust gateway.
2. The gateway checks its in-memory denylist, backed by `/state/blocks.json`. An allowed request is forwarded to a fixed app target. A blocked request returns HTTP 403 with the matching incident ID and writes a gateway log.
3. The app checks dummy credentials and writes one real structured JSON line to its mounted log file. Passwords are never logged.
4. The API container mounts `/logs` read-only. A Tokio sensor polls four known files, preserves partial lines, limits line size and sends parsed events over `mpsc`. SQLite ignores duplicate event IDs.
5. The core crate computes TACG edges and an explainable risk score. Incidents, memberships, edges, entities and events are persisted in SQLite. The WebSocket broadcasts state changes.

## Control and verification plane

For risk >=85 and confidence >=85, the response engine records `ACTION_REQUESTED`, calls gateway `/internal/block`, and records the actual result. It then asks the fixed client to retry a login. The client returns the observed HTTP status and gateway JSON. The response engine requires all three: block applied, HTTP 403, and an incident ID match. Only then is the incident `CONTAINED`. A refused block or nonmatching response produces `RESPONSE_FAILED`. Verification attempts and gateway blocks are stored in separate SQL tables.

The intentional failure switch makes the gateway return HTTP 503 for `/internal/block`. The verification request then reaches the app and returns HTTP 401, proving containment failed. No host firewall is changed.

## Crates and storage

- `logshield-core`: event types, normalizer, baseline, TACG, risk, incident and response state machine. No web dependency.
- `logshield-api`: Axum routes, read-only sensor, Tokio channel, SQLx persistence, WebSocket and response orchestrator.
- `logshield-lab`: Rust binary with fixed app, gateway and controlled-client roles.
- `frontend`: React/TypeScript evidence views.

SQLite tables: `events`, `entities`, `incidents`, `incident_events`, `correlation_edges`, `responses`, `verification_attempts`, `gateway_blocks`. The gateway also persists its active denylist to a mounted file so a restart does not silently remove a live block.
