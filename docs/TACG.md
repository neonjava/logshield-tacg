# Temporal Attack Correlation Graph

## Problem and contribution

A five-failure attack can be spread over three hosts as 2/2/1. A per-host threshold of five misses it. TACG correlates source identity, account, host and time to reconstruct a cross-host story. Event correlation exists elsewhere; this project's contribution is its transparent graph, cross-host threshold proof, attack-chain scoring, automated gateway action and observed verification.

## Nodes and edges

Each normalized log record is a node. Events from the same source inside a 10-minute window are sorted by time. Adjacent nodes receive an edge when they share an entity and have temporal proximity. Edge reasons list shared source, destination, username, host, service or request ID, plus a risky transition. Temporal weight is `exp(-Δt / 90 seconds)`; close events have stronger links.

Gateway deny logs remain available as response evidence but do not count as app attack nodes. The graph is an in-memory Rust structure; SQL stores its edge evidence.

## Candidate patterns

- **Distributed authentication:** at least five failures from one source across three hosts. Each host can remain below five.
- **Brute force:** at least six failures in the window.
- **Multi-stage:** at least two failures followed by a successful login, a lab privilege action and an outbound-style action. The current prototype recognizes presence and pairwise transitions; stricter full ordering is future work.
- **Unauthorized access:** an app unauthorized-access event.

Normal successful logins alone are not candidates.

## Explainable risk

`risk = min(100, 20R + 20T + 15E + 20X + 10C + 15B + chain_bonus)`

`R` is event rarity, `T` mean temporal strength, `E` mean shared-entity strength, `X` transition risk, `C` cross-host score and `B` behavioral deviation. The baseline learns usual user hours, hosts, source relationships and normal event volume from benign records. The explicit bonus is 8 for distributed auth, 12 for brute force and 25 for a multi-stage chain. Each weighted contribution and the bonus are stored in the incident JSON and shown in the UI.

For a distributed pattern with `R=.8, T=.98, E=.95, X=.75, C=1, B=.65`, the score is `16 + 19.6 + 14.25 + 15 + 10 + 9.75 + 8 = 92.6`, rounded to 93. Real timings and entity links make the precise score vary. A response requires both risk >=85 and detection confidence >=85.

## Limits

Source-IP grouping can be fooled by NAT or rotating source identities. The current graph uses adjacent event links rather than exhaustive path search. The small baseline and hand-tuned thresholds need calibration on representative labeled data before operational deployment. Graph explanations are evidence, not a probabilistic guarantee of malicious intent.
