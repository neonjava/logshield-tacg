# Pitch and judge preparation

## 20-second pitch

“Traditional monitoring often evaluates security events independently. LogShield TACG correlates events across time, hosts, users and network identities to reconstruct the complete attack chain. It calculates an explainable risk score, performs confidence-controlled automated containment in an authorized environment, and verifies whether the response succeeded. LogShield TACG's security engine is implemented natively in Rust, allowing the correlation pipeline to process security events concurrently while maintaining memory safety and predictable performance.”

## Likely questions

**What is the innovation?** A transparent temporal graph joins weak evidence into a sequence and scores the chain, including activity spread across hosts.

**Why not an ML black box?** The hackathon goal needs defensible explanations. A statistical baseline supplements explicit correlation rules and every score component is visible.

**How does low and slow work?** Five failures from one source across three hosts share a temporal window and source identity; no host needs to cross a local threshold.

**Does it block an attacker?** No. Responses are local records and verification observes only submitted test events. Production integrations would require separate authorization.

**Why Rust?** Type and memory safety, low overhead and Tokio concurrency make it suitable for a long-running security agent.

**What are the main limitations?** Source-IP grouping, simple parser coverage, short baseline history and a demo-sized observation window. These are explicit future work, not hidden claims.
