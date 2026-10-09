# LogShield TACG — Hackathon Demonstration & Presentation Guide

This guide provides the exact demonstration flow for university hackathon presentations and technical judging sessions.

---

## 1. Quick Environment Setup

Before the demo, launch the local environment:

```bash
cd /home/neonjava/logshield
cargo run -p logshield-ingest --bin logshield-agent -- init-demo
cargo build --release --workspace
docker compose build
docker compose up -d
cd frontend && npm run dev
```

- **SOC Web Dashboard:** `http://127.0.0.1:5173`
- **Backend API:** `http://127.0.0.1:3000`

---

## 2. The Two-Minute Executive Pitch (Judge Walkthrough)

| Time | Screen / Action | Narration & Key Value Proposition |
|---|---|---|
| **0:00–0:15** | **Overview Tab**<br>Click **Clear lab data** | "Notice the live indicators: Gateway ONLINE, Sensor ONLINE, TACG ONLINE, Database ONLINE, and 3 Lab Replicas active. These are live compiled Rust processes running inside isolated Docker networks, not mock UI widgets." |
| **0:15–0:30** | **Lab Tab**<br>Click **Start normal traffic** | "We inject legitimate employee logins across our server replicas. Observe the Events tab: real JSON structured logs are ingested. No incidents or critical alerts are generated because normal behavior is baseline-aware." |
| **0:30–0:50** | **Lab Tab**<br>Click **Start distributed auth test** | "Now we simulate a distributed attacker sending a 2/2/1 brute force attack across three separate application replicas (`app-a`, `app-b`, `app-c`). Every individual server sees at most two failures — well below any traditional single-host threshold of five." |
| **0:50–1:15** | **Incidents Tab**<br>Click the generated Critical Incident | "LogShield’s Temporal Attack Correlation Graph connected the dots across time and infrastructure. Here is the in-memory graph reconstruct: 5 related failures spanning 3 hosts, with decaying temporal edges linking them into a single coherent incident." |
| **1:15–1:40** | **Score Breakdown**<br>Point to explainability bars | "Every point in the risk score is 100% explainable in native Rust — no black-box LLM hallucinations. Rarity: 16 pts, Temporal: 20 pts, Entity: 14 pts, Transition: 15 pts, Cross-host: 10 pts, Deviation: 10 pts, plus structural chain bonus. Risk = 93/100." |
| **1:40–2:00** | **Containment Proof**<br>Show Response panel | "Because risk and evidence strength exceeded 85, our automated response adapter dynamically blacklisted the attacker at the gateway. A verification retry was dispatched and received an actual HTTP 403 Forbidden. Containment is verified." |

---

## 3. Hands-On Interactive Demonstrations

### Demo A: CLI Direct Target Injection
You can execute the 2/2/1 attack directly via `curl` from the terminal:

```bash
cd /home/neonjava/logshield
curl -sS -X POST http://127.0.0.1:3000/api/lab/clear

# 2 failures on app-a, 2 on app-b, 1 on app-c
for app in app-a app-a app-b app-b app-c; do
  curl -sS -X POST http://127.0.0.1:3000/api/lab/attempt \
    -H 'Content-Type: application/json' \
    -d "{\"app\":\"$app\",\"operation\":\"login\",\"source\":\"attacker-lab\",\"password\":\"wrong\"}"
  echo
  sleep 1
done
```
Inspect the dashboard: on the 5th attempt, the incident is synthesized and verified HTTP 403 containment is displayed.

### Demo B: Forced Response Failure (Failure Modes Demonstration)
To demonstrate resilience when the firewall/gateway is unreachable:
1. In the **Lab** tab, toggle **Force response failure**.
2. Click **Start distributed auth test**.
3. Notice that the incident is flagged as `RESPONSE_FAILED` with an alert prompting human SOC intervention, showing LogShield never blindly assumes containment succeeded.

### Demo C: Multi-Stage Attack Kill-Chain
1. In the **Lab** tab, click **Start multi-stage test**.
2. LogShield observes:
   - Stage 1: Failed password attempt.
   - Stage 2: Successful login.
   - Stage 3: Privilege escalation action.
   - Stage 4: Outbound network activity / data exfiltration.
3. TACG recognizes the strict chronological kill-chain and issues an immediate Critical incident with a +25 kill-chain bonus.

---

## 4. Live Judge Code & Benchmark Verification

Judges often ask: *"How do we know this isn't just hardcoded rules that overfit to this one demo?"*

Run the independent 60-scenario ablation benchmark suite directly in front of the judges:

```bash
cargo test -p logshield-core --test benchmark_suite -- --nocapture
```

Show the live terminal output:
- **Full TACG:** Precision 1.000, Recall 0.857, F1 0.923, FPR 0.000.
- **Ablated TACG (No Graph Edges):** Recall drops to 0.571, F1 drops to 0.727 (proves mathematical necessity of graph edges).
- **Stateful Rules Engine:** Recall drops to 0.714, F1 drops to 0.833.
- **Benign Criticals:** 0 across all 60 scenarios (zero legitimate users blocked).

Run the full workspace test suite to demonstrate production-grade engineering quality:

```bash
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```
