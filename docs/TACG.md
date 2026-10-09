# Temporal Attack Correlation Graph (TACG)

For full mathematical equations, graph theory models, and weighting parameters, see [docs/ALGORITHM.md](ALGORITHM.md). For empirical evaluation and ablation study results, see [docs/EVALUATION.md](EVALUATION.md). For engineering boundaries and threat model limits, see [docs/LIMITATIONS.md](LIMITATIONS.md).

---

## 1. Problem and Contribution

A five-failure attack can be distributed across three server replicas as a 2/2/1 pattern. A per-host threshold of five misses it completely. Traditional centralized source counters flag benign corporate NATs and miss rotating-IP botnets.

TACG correlates source identity, targeted account, host, and time to reconstruct a cross-host attack story. This project's contribution is:
- A transparent, in-memory attributed temporal graph in native Rust.
- Dual-anchor clustering (source-anchored and identity-anchored) to detect both single-source and rotating-source distributed attacks.
- Rigorous behavioral baseline and human typo/MFA retry discounting that prevents false containment.
- Verified automated gateway containment with cryptographic proof of HTTP 403 enforcement.

---

## 2. Nodes, Edges, and Clustering

### Graph Construction
- **Nodes:** Normalized security log records.
- **Edges:** Time-decayed links between events occurring within a 10-minute sliding window ($W_{\max} = 600$s).
- **Temporal Weight:** $W_{\text{temporal}} = \exp(-\Delta t / 90\,\text{s})$; close events have stronger links.
- **Entity Weight:** Overlap of shared source IP, destination IP, account/username, hostname, service, and request ID.

### Dual-Anchor Clustering
1. **Pass 1: Source-Anchored Clustering:** Groups events sharing the same `source_ip` within the 10-minute sliding window. Detects localized brute-force, single-source distributed credential probing across hosts, and single-source multi-stage kill chains.
2. **Pass 2: Identity-Anchored Clustering:** For events targeting the same account (`username`) originating from $\ge 2$ distinct sources. Connects rotating-source botnets and distributed password spraying that evade single-IP counters.

---

## 3. Candidate Patterns & Typo Discounting

- **Distributed Authentication:** A connected same-account failure path contains at least 5 failures across $\ge 3$ hosts.
- **Rotating Sources:** At least 4 failures targeting a single account across $\ge 2$ distinct source IPs.
- **Brute Force:** At least 6 failures for one account on one host in the window.
- **Multi-Stage Kill-Chain:** Failure $\to$ Success $\to$ Privilege Action $\to$ Outbound Action in strict chronological order.
- **MFA Push Fatigue:** $\ge 3$ consecutive MFA failures.
- **Human Typo Tolerance:** 1–2 failed logins immediately followed by success by a familiar user on a known host is recognized as routine typing error and discounted, producing zero false alarms.
- **Routine MFA Retries:** Up to 3 MFA retries spaced over normal human cadence by a familiar user is recognized as token expiration and suppressed from critical containment.

---

## 4. Explainable Risk Formulation

$$\text{Risk} = \min\left(100, \, \lfloor 20 \cdot R + 20 \cdot \bar{T} + 15 \cdot \bar{E} + 20 \cdot X + 10 \cdot C + 15 \cdot B + \text{Bonus} \rfloor\right)$$

- $R$: Event rarity relative to baseline traffic.
- $\bar{T}$: Mean time-decayed proximity of graph edges.
- $\bar{E}$: Mean entity overlap ratio.
- $X$: Transition risk between sequential event types.
- $C$: Cross-host dispersion score (1.0 if $\ge 3$ distinct hosts).
- $B$: Baseline statistical deviation from learned user profiles.
- $\text{Bonus}$: Pattern bonuses (+25 multi-stage, +20 compromise, +18 MFA fatigue, +16 rotating sources, +8 distributed auth).

Automatic containment requires both $\text{Risk} \ge 85$ and $\text{Evidence Strength} \ge 85$ with an approved response adapter.

---

## 5. Engineering Limits

For full details, see [docs/LIMITATIONS.md](LIMITATIONS.md). Attacks throttled to $> 600$ seconds between attempts fall outside the real-time sliding graph window. First-time logins from novel locations without prior history are flagged as Medium-tier anomalies (alerts SOC) rather than Critical auto-containment to protect traveling employees.
