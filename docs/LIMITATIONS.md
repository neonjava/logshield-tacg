# LogShield TACG — Engineering Limitations & Operating Boundaries

In security engineering, transparent disclosure of design constraints and known boundaries is essential. LogShield TACG is designed for explainable, self-hosted correlation of distributed security events. This document outlines the deliberate trade-offs, operating boundaries, and areas outside the system's design envelope.

---

## 1. Temporal Correlation Window (600-Second Horizon)

### The Constraint
TACG maintains an in-memory sliding correlation window of $W_{\max} = 600\,\text{seconds}$ (10 minutes) with exponential time decay ($\tau = 90\,\text{s}$).

### Threat Model Implication: "Low-and-Slow" Attacks
An adversary who intentionally throttles their attacks so that each attempt occurs more than 10 minutes apart (e.g., 1 failed login attempt every 12 minutes, or 5 attempts over 60 minutes) will **not** be linked into a single TACG incident path. This is demonstrated empirically in our evaluation suite (`distributed_beyond_window` case).

### Design Trade-Off Rationale
An unbounded correlation window causes unbounded in-memory graph growth, leading to memory exhaustion and latency degradation under sustained ingestion. The 10-minute window was chosen to capture active automated brute-force attacks, rapid botnet credential stuffing, and multi-stage exploitation sequences while maintaining predictable memory usage ($O(|V|)$ bounded by time).

### Future Mitigation
Long-term threat detection across hours or days should be handled by a secondary persistent aggregation tier (e.g., daily identity risk counters in PostgreSQL) rather than real-time graph edge traversal.

---

## 2. Zero-History Anomalies & Travel Devices

### The Constraint
TACG's familiarity discounting relies on an established behavioral baseline ($\ge 3$ prior successful logins from known IPs/hosts).

### Threat Model Implication
When a legitimate employee logs in for the first time from a novel source (e.g., hotel Wi-Fi, mobile carrier IP, foreign conference):
- The user has zero historical familiarity from that source IP.
- The single successful login produces an unfamiliar source event (`new_source_success`).

### Design Trade-Off Rationale
If the detector classified any new-source login as an attack, remote employees and travelers would constantly suffer false-positive containment. 

LogShield resolves this by scoring single new-source logins as **Medium-tier behavioral anomalies** (risk score 50–65) rather than High or Critical threats. This alerts SOC analysts in the dashboard without triggering automatic gateway blocking (`benign_critical = 0`).

---

## 3. Scope Boundary: Correlation vs. Inline Packet/Payload Inspection

### The Constraint
LogShield is a **log-based correlation engine**, not an inline Web Application Firewall (WAF), Endpoint Detection and Response (EDR) agent, or deep packet inspection (DPI) tool.

### What TACG Detects
- Multi-host authentication probing (2/2/1 across replicas).
- Rotating IP botnets targeting single accounts.
- Ordered multi-stage kill chains (Failed Login $\to$ Login $\to$ Privilege Escalation $\to$ Exfiltration).
- MFA push fatigue attacks.
- Compromised accounts (login following brute-force failures).

### What TACG Does NOT Detect
- Single-request zero-day exploits (e.g., Log4Shell or unauthenticated RCE executed in a single HTTP request without prior failures).
- Memory-level exploit payloads (buffer overflows, heap spraying) inside application binaries.
- Encrypted traffic inspection without application-level log emission.

LogShield relies on application, auth, and system logs emitted by existing services.

---

## 4. Evidence Strength Score vs. Calibrated Probability

### The Constraint
The LogShield API includes a field named `confidence` (0–100) alongside `risk` (0–100).

### Definition
- `confidence` is a **rule-based evidence strength metric**, calculated from graph edge density, entity match ratio, and corroborating server count.
- **It is NOT a Bayesian posterior probability.** An incident with a confidence of `88` means strong structural and multi-source evidence was observed; it does **not** mean there is an 88% statistical likelihood that the user is malicious.

---

## 5. Ingestion Scale & Memory Model

### Current Architecture
- LogShield runs in-memory graph correlation in native Rust protected by `tokio::sync::Mutex` / `RwLock`.
- In local benchmarks, the pipeline comfortably processes thousands of events per second with sub-millisecond evaluation latency.

### Boundary for Enterprise Workloads (>50,000 events/sec)
- In a massive enterprise deployment generating tens of thousands of logs per second across thousands of hosts, a single-process in-memory mutex would experience lock contention.
- Enterprise scale requires horizontal partitioning: sharding the event stream by identity hash or organization tenant across independent worker nodes, backed by a distributed log broker (such as Apache Kafka).

---

## 6. Deployment Responsibilities in Production

In the local lab, LogShield runs with pre-configured Docker networking, synthetic attacker tools, and unauthenticated lab APIs. For private production deployment:
1. **Operator Token:** Non-lab API access must have `OPERATOR_TOKEN` set and enforced.
2. **TLS Termination:** The API and agents must communicate over HTTPS/TLS via a reverse proxy (e.g., NGINX, Caddy, or Envoy).
3. **Agent Credentials:** Each server's `logshield-agent` requires a unique ingestion secret.
4. **Log Provenance:** Log files on monitored hosts must be read-only for the agent and protected against tampering by the host operating system's access controls.
