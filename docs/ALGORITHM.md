# LogShield TACG — Algorithm & Mathematical Specification

This document provides a complete technical specification of the **Temporal Attack Correlation Graph (TACG)**, its graph construction principles, dual-anchor clustering, temporal decay equations, behavioral baseline integration, and the explainable risk scoring formulation.

---

## 1. Problem Formulation: Why Scalar Rules and Counters Fail

Traditional Security Information and Event Management (SIEM) systems and Intrusion Detection Systems (IDS) rely heavily on either:
1. **Per-Host Threshold Counters** (e.g., "Alert if host $H$ experiences $> 5$ failed logins within 5 minutes"), or
2. **Centralized Source Counters** (e.g., "Alert if source IP $S$ triggers $> 5$ failed logins globally").

Both approaches suffer from critical blind spots in distributed modern environments:

```
┌────────────────────────────────────────────────────────────────────────┐
│                        Cross-Host Evasion (2/2/1)                      │
│                                                                        │
│   Attacker IP: 198.51.100.99                                           │
│       │                                                                │
│       ├─► Host A (app-a): 2 failures   <-- Per-host threshold (5): OK  │
│       ├─► Host B (app-b): 2 failures   <-- Per-host threshold (5): OK  │
│       └─► Host C (app-c): 1 failure    <-- Per-host threshold (5): OK  │
│                                                                        │
│   Result: All 3 hosts report "normal" traffic. Attack goes undetected. │
└────────────────────────────────────────────────────────────────────────┘
```

Conversely, a centralized source counter triggers false positives on shared network environments (e.g., corporate NAT gateways or VPN egresses where multiple legitimate employees share an external IP). Furthermore, rotating source attacks (botnets alternating IP addresses) bypass source-based counters entirely because each IP generates only 1 event.

TACG solves these problems by constructing an **in-memory temporal correlation graph** that links events across time, accounts, hosts, and services, evaluating the structured topology of the activity rather than flat counters.

---

## 2. Graph Formalism: Nodes, Edges, and Temporal Decay

### 2.1 Graph Representation
Let $G = (V, E)$ be an attributed temporal graph where:
- Each node $v_i \in V$ represents a normalized security event:
  $$v_i = (\text{id}_i, \, t_i, \, \text{type}_i, \, \text{src}_i, \, \text{host}_i, \, \text{user}_i, \, \text{svc}_i, \, \text{req}_i)$$
- Each edge $e = (v_i, v_j) \in E$ represents a causal or temporal relationship between events $v_i$ and $v_j$ occurring within a sliding time window $W_{\max} = 600\,\text{seconds}$ (10 minutes).

### 2.2 Temporal Edge Weight ($W_{\text{temporal}}$)
The strength of a relationship decays exponentially with the time difference $\Delta t = |t_j - t_i|$:

$$W_{\text{temporal}}(v_i, v_j) = \exp\left(-\frac{\Delta t}{\tau}\right) \quad \text{for } 0 \le \Delta t \le W_{\max}$$

Where $\tau = 90.0\,\text{seconds}$ is the decay constant. Events occurring in rapid succession ($\Delta t < 10\,\text{s}$) have $W_{\text{temporal}} \approx 0.90 - 1.00$, while events spaced 5 minutes apart decay to $W_{\text{temporal}} \approx 0.036$. Events beyond 600s drop out of the sliding graph window.

### 2.3 Entity Match Weight ($W_{\text{entity}}$)
Edges are established when events share one or more entity attributes:
$$W_{\text{entity}}(v_i, v_j) = \frac{\sum_{k} w_k \cdot \mathbb{I}(v_i.k = v_j.k)}{\sum_{k} w_k}$$

Attributes evaluated include:
- `source_ip` (Weight = 1.0)
- `destination_ip` (Weight = 0.8)
- `username` (Weight = 1.0)
- `hostname` (Weight = 0.7)
- `service` (Weight = 0.5)
- `request_id` (Weight = 1.0)

### 2.4 Transition Weight Matrix ($X_{ij}$)
Certain sequential event transitions indicate attacker progression through an attack kill-chain. TACG applies a domain transition matrix:

| Prior Event ($v_i$) | Successor Event ($v_j$) | Transition Score ($X_{ij}$) | Rationale |
|---|---|---|---|
| `FailedLogin` | `FailedLogin` | 0.65 | Repeated credential probing |
| `FailedLogin` | `SuccessfulLogin` | 0.80 | Credential stuffing success / brute-force completion |
| `SuccessfulLogin` | `PrivilegeAction` | 0.85 | Post-exploitation privilege escalation |
| `PrivilegeAction` | `UnusualNetworkActivity` | 0.95 | Data exfiltration / command-and-control egress |
| `MfaFailure` | `MfaFailure` | 0.85 | MFA push fatigue / brute-force |
| `WebRequest` | `WebRequest` | 0.10 | Ambient normal web traffic |

---

## 3. Dual-Anchor Clustering Architecture

To defend against both centralized attacks and distributed rotating IP botnets, TACG executes a two-pass clustering strategy:

```
                          Incoming Event Stream
                                    │
                                    ▼
       ┌────────────────────────────────────────────────────────┐
       │     Pass 1: Source-Anchored Correlation                │
       │     Group by source_ip within sliding window W         │
       │     - Brute-force attacks                              │
       │     - Single-source cross-replica attacks (2/2/1)      │
       │     - Single-source multi-stage kill chains            │
       └────────────────────────────┬───────────────────────────┘
                                    │ Uncorrelated / Residual Events
                                    ▼
       ┌────────────────────────────────────────────────────────┐
       │     Pass 2: Identity-Anchored Correlation              │
       │     Group by targeted username across ≥ 2 distinct IPs │
       │     - Rotating IP botnets                              │
       │     - Distributed password sprays                      │
       │     - Cloud egress credential stuffing                 │
       └────────────────────────────────────────────────────────┘
```

### Pass 1: Source-Anchored Clustering
Groups events sharing the same `source_ip`. For each group:
1. Sort events chronologically.
2. Build adjacent temporal edges $e = (v_k, v_{k+1})$.
3. Construct account-specific failure paths: consecutive `FailedLogin` events for the same `username` where decayed edge strength $\ge 0.35$.
4. Check candidates:
   - **Distributed Cross-Host:** At least 5 failures across $\ge 3$ distinct hosts.
   - **Local Brute-Force:** At least 6 failures targeting one host.
   - **Multi-Stage Chain:** Ordered sequence: FailedLogin $\to$ SuccessfulLogin $\to$ PrivilegeAction $\to$ UnusualNetworkActivity.
   - **MFA Fatigue:** $\ge 3$ consecutive MFA failures.
   - **Success After Failures:** Successful login preceded by $\ge 2$ failures within 600s.

### Pass 2: Identity-Anchored Clustering
Events not forming a single-source incident are checked for targeted account correlation:
1. Group residual events by `username`.
2. Filter for groups originating from **$\ge 2$ distinct source IPs**.
3. If an account experiences $\ge 4$ failures across multiple rotating sources, TACG flags an **Identity-Anchored Rotating Source Attack**.

---

## 4. Behavioral Baseline & Familiarity Discounting

A critical flaw in naive correlation engines is mistaking benign user errors (e.g., a typo in a password, an expired TOTP MFA token) for attacks. TACG integrates a rolling behavioral baseline to distinguish routine human mistakes from genuine threats.

### 4.1 Familiarity Profile
For every user, TACG tracks historical benign operations:
- Set of known IP addresses $S_{\text{known}}(u)$
- Set of known hostnames $H_{\text{known}}(u)$
- Historical successful login count $N_{\text{success}}(u)$

An event sequence is classified as **Familiar Authentication** if:
$$N_{\text{success}}(u) \ge 3 \quad \land \quad \text{src} \in S_{\text{known}}(u) \quad \land \quad \text{host} \in H_{\text{known}}(u)$$

### 4.2 Typo & Mistake Discounting
When activity matches a familiar user profile:
1. **Password Typos:** 1–2 failed logins immediately followed by a successful login on a known host/source is categorized as a routine human typo. Risk score is discounted to 0, preventing false alerts.
2. **MFA Token Retries:** Up to 3 MFA retries spaced over normal human cadence (20–40s) by a familiar user on a known host does not trigger critical alarm or automatic containment.
3. **New Device / Travel Anomaly:** A successful login from a previously unseen IP without prior failures is categorized as a **Medium-tier behavioral anomaly** (risk score 50–65). It alerts SOC operators for review but strictly suppresses automatic gateway blocking, preventing disruption to legitimate traveling employees.

---

## 5. Explainable Risk Score Formulation

TACG rejects black-box outputs. Every incident produced by LogShield computes an explicit, bounded score between 0 and 100 with all component contributions stored in the database and visible in the UI:

$$\text{Risk} = \min\left(100, \; \lfloor 20 \cdot R + 20 \cdot \bar{T} + 15 \cdot \bar{E} + 20 \cdot X + 10 \cdot C + 15 \cdot B + \text{Bonus} \rfloor\right)$$

### Component Definitions

| Component | Weight | Range | Definition |
|---|---|---|---|
| **$R$ (Rarity)** | 20 | $[0.0, 1.0]$ | Inverse frequency of event type relative to baseline traffic volume. |
| **$\bar{T}$ (Temporal)** | 20 | $[0.0, 1.0]$ | Mean time-decayed proximity of adjacent graph edges: $\frac{1}{|E|}\sum W_{\text{temporal}}$. |
| **$\bar{E}$ (Entity)** | 15 | $[0.0, 1.0]$ | Mean entity overlap ratio across graph edges. |
| **$X$ (Transition)** | 20 | $[0.0, 1.0]$ | Maximum or mean risk transition score according to the transition matrix. |
| **$C$ (Cross-Host)** | 10 | $\{0.0, 1.0\}$ | 1.0 if events span $\ge 3$ distinct hostnames; 0.0 otherwise. |
| **$B$ (Behavior)** | 15 | $[0.0, 1.0]$ | Baseline statistical deviation from learned user profiles. |
| **$\text{Bonus}$** | Variable | $[0, 25]$ | Explicit structural topology bonus: |
| | | +25 | Full 4-stage kill-chain match |
| | | +20 | Compromise verified (login success following multiple failures) |
| | | +18 | MFA push fatigue detected |
| | | +16 | Identity-anchored rotating source attack |
| | | +8 | Distributed cross-replica authentication probe |

### Risk Tiers & Automated Action Threshold
- **Low (0–39):** Informational activity.
- **Medium (40–69):** Behavioral anomaly or minor event cluster. Logged for analyst review.
- **High (70–84):** Significant suspicious pattern. High-priority ticket generated.
- **Critical (85–100):** High-confidence active threat. Automatic containment (e.g. gateway denylist) is authorized **if and only if**:
  1. $\text{Risk} \ge 85$,
  2. $\text{Evidence Strength} \ge 85$, and
  3. An approved, verified response adapter (e.g. LogShield Gateway) is active.
