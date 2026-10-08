# Architecture

1. **Ingestion:** Axum accepts normalized JSON, bounded multipart files and local demo events. A Tokio `mpsc` channel decouples requests from processing.
2. **Normalization:** Rust parsers recognize common Linux SSH lines, firewall-style key/value lines and JSON events. Missing fields remain `Option` values.
3. **Storage:** SQLx persists event and incident JSON in SQLite using bound queries. The in-memory graph is rebuilt from recent event rows; no graph database is required.
4. **Correlation:** TACG groups events by source in a 10-minute window, sorts by time, and creates consecutive graph edges when temporal and entity evidence is present. Edge reasons are retained.
5. **Risk:** Six visible weighted features plus a chain bonus determine the score. Severity is a direct threshold mapping.
6. **Response:** Critical incidents enter `PENDING_VERIFICATION`, record simulated block/quarantine/evidence actions, then verify after a three-second observation window. Continued suspicious activity changes the result to `RESPONSE_FAILED` and records simulated escalation.
7. **Delivery:** REST provides snapshots. WebSocket broadcasts changes. React renders the incident chain, feature contributions, host activity and response state.

The core crate has no web dependency, allowing reuse in a daemon or agent. Only the API crate owns SQLite and transport. All cybersecurity logic is Rust.
