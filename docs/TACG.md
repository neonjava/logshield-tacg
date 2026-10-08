# Temporal Attack Correlation Graph

## Problem

Single-event thresholds miss activity spread across hosts or stages. TACG asks whether weak events form a coherent attack story.

## Nodes and edges

Each normalized `SecurityEvent` is a node. Events from one source IP within 10 minutes are sorted by timestamp. Consecutive nodes receive an edge if they share an entity and have meaningful temporal proximity. Edge metadata records same source, destination, user, host or service plus risky transitions. Temporal strength is `exp(-Δt / 90 seconds)`. A six-second gap contributes about 0.94; a 90-second gap about 0.37.

## Correlation features

- **Rarity:** rarity of suspicious event patterns, with full-stage chains rarer than repeated failures.
- **Temporal:** mean time-decay strength between adjacent events.
- **Entity:** shared source, destination, username, host or service with explicit weights.
- **Transition:** risky ordered pairs such as failure → success, success → privilege and privilege → outbound activity.
- **Cross-host:** same source failing against at least two hosts, with strongest score at three hosts and five failures.
- **Behavior:** simple normal profile learns user hours, hosts, source IPs and common services from benign events; a burst score supplements novelty.

A candidate incident requires a meaningful pattern: at least six failures, the five-failure three-host pattern, a full multi-stage chain, or unauthorized access. Thus normal logins do not become incidents solely due to time proximity.

## Score

`risk = min(100, 20R + 20T + 15E + 20X + 10C + 15B + chain_bonus)`

All six features are in `[0,1]`. The bonus is 32 for the full multi-stage chain, 18 for the distributed pattern and 12 for brute force. Every term is returned to the UI. For example, `R=.9, T=.9, E=.8, X=.75, C=1, B=.65` gives `18 + 18 + 12 + 15 + 10 + 9.75 + 18 = 100.75`, capped at 100. The bonus intentionally makes a coherent attack sequence outrank isolated anomalies.

## Limitations

Source IP is the primary grouping key, so NAT or rotating IPs can distort chains. The prototype links consecutive events and does not perform full path search or identity resolution. The baseline is small and demo-oriented. Thresholds are deterministic and explainable, but require calibration against real labeled enterprise data before operational use.
