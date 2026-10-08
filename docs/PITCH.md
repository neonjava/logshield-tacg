# Pitch

“Traditional per-host threshold detection may miss weak malicious activity distributed across several systems. LogShield TACG correlates those events across identities, hosts and time, reconstructs the attack chain, performs an automated defensive action, and verifies that the response actually succeeded. Its security engine is implemented natively in Rust for memory safety, predictable performance and concurrent log processing.”

## Likely judge questions

**Are the events real?** Yes. The controlled client sends HTTP requests through the gateway; each app writes a JSON line; the read-only Rust sensor parses it. The generator never inserts attack events into TACG.

**What is novel?** We do not claim to invent event correlation. Our contribution is an explainable temporal graph with cross-host attack reconstruction, score decomposition, gateway containment and HTTP verification.

**Why is 2/2/1 suspicious?** Five failures from one source and account span three hosts inside a short window, even though no host reaches the threshold of five.

**How is containment verified?** The Rust client retries through the gateway. The engine requires an applied block, HTTP 403 and a matching incident ID before setting `CONTAINED`.

**What happens if blocking fails?** Lab mode forces gateway HTTP 503; the retry reaches the app and gets HTTP 401. The incident stays `RESPONSE_FAILED` and requires human intervention.

**Can it target the university network?** No. The lab client accepts only three named apps; Docker networks are internal; no external attack target parameter exists.

**Why Rust?** Strong types, memory safety, Tokio concurrency and low overhead suit a future long-running sensor or gateway.

**Production gaps?** Authentication and mTLS, source identity derived from the network, robust parser coverage, baseline calibration, durable sensor offsets, rule tuning and analyst feedback.
