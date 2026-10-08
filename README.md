# LogShield TACG

**AI26CY03 · Log-Based Intrusion Detection · Rust security engine**

LogShield reconstructs an attack story from weak log events that a single-event rule might miss. Its Temporal Attack Correlation Graph (TACG) links events by source, account, host, service, time and security-relevant transitions. The result is an incident with a visible chain, a reproducible score, recommended actions and simulated response verification.

## Why Rust

The entire security pipeline and API are native Rust. Memory safety, strong types, predictable performance, Tokio concurrency and low runtime overhead fit a long-running monitoring agent. React only renders data returned by the Rust engine.

## Architecture

`log files / JSON / demo → Axum API → Tokio mpsc → Rust normalizer → TACG → risk and incident engine → simulated response → verification → SQLite → WebSocket / REST → React`

See [architecture](docs/ARCHITECTURE.md) and [algorithm](docs/TACG.md).

## Quick start

Requires stable Rust, Node 22+ and npm.

Terminal 1:

```bash
cd /home/neonjava/logshield
cargo run -p logshield-api
```

Terminal 2:

```bash
cd /home/neonjava/logshield/frontend
npm install
npm run dev
```

Open <http://127.0.0.1:5173>. The API listens only on `127.0.0.1:3000`. SQLite is created at `logshield.db` in the backend process working directory. For a clean demo, stop the backend and remove that local demo database before restarting.

## Demo scenarios

- **Normal:** benign logins, requests and service activity; no incident.
- **Brute force:** eight failures on one host; incident and alert.
- **Distributed low and slow:** two failures on server A, two on B and one on C from the same source. Individually weak events become one cross-host incident.
- **Multi-stage:** connection → port activity → failures → successful login → privilege action → outbound activity. Critical incident, automatic simulated response, verification and containment.

Use the four dashboard buttons, or `curl -X POST http://127.0.0.1:3000/api/demo/multistage`. The exact [two-minute script](docs/DEMO.md) is presentation ready.

## Risk and response

Six normalized features contribute 20, 20, 15, 20, 10 and 15 possible points respectively: rarity, temporal proximity, entity relationship, risky transitions, cross-host behavior and baseline deviation. A visible chain bonus is added and the total is capped at 100. The incident detail shows each contribution and every contributing event. Thresholds: low 0–39, medium 40–69, high 70–84, critical 85–100.

Critical response is a **simulation only**: a source block and quarantine are recorded as simulated actions, evidence IDs are preserved and verification checks for new suspicious events after the response. No firewall, account or external system is modified. If activity continues, the incident becomes `RESPONSE_FAILED` and simulated escalation is recorded. This is a prototype observation window, not proof of real-world containment.

## API

| Method | Endpoint | Purpose |
|---|---|---|
| POST | `/api/events` | Submit a normalized JSON security event |
| POST | `/api/logs/upload` | Upload UTF-8 `.log`, `.txt`, or `.jsonl`, max 1 MiB |
| GET | `/api/events` | Recent events |
| GET | `/api/incidents` | Incidents |
| GET | `/api/incidents/{id}` | Full chain and score |
| GET | `/api/stats` | Dashboard totals |
| POST | `/api/demo/{normal,bruteforce,distributed,multistage}` | Generate local data |
| POST | `/api/incidents/{id}/respond` | Simulate and verify response |
| GET | `/api/incidents/{id}/response` | Response status |
| WS | `/ws/events` | Live event and incident notices |

Sample upload: `curl -F file=@demo/logs/sample-auth.log http://127.0.0.1:3000/api/logs/upload`.

## Tests and checks

```bash
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test
cargo build
cd frontend && npm run build
```

Native Rust tests cover parsing, time decay, cross-host detection, multi-stage reconstruction, normal false-positive protection, brute-force detection, scoring boundaries and response success/failure.

## Security and limitations

The API binds to localhost, uploads are size and extension limited, lines are never executed, SQL uses bound parameters and React escapes text. The local API has no authentication because it is a demo; do not expose it to a network. Parser support is intentionally narrow. Baselines are lightweight and derived from available benign events rather than trained over long histories. Correlation currently groups by source IP in a 10-minute window and stores up to 2,000 recent events for analysis. A production version would need authenticated ingestion, robust parser plugins, durable baseline snapshots, stronger identity resolution, rate limits, analyst feedback and real response integrations with explicit authorization.
