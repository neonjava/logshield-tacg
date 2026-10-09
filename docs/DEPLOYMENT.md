# Private self-hosted deployment

This is the first supported deployment direction for LogShield TACG. It is an integration beta; the Docker Compose stack is an isolated test environment, not a hardened production manifest.

## Trust boundaries

- Keep `API_BIND` on `127.0.0.1:3000` unless the API is on a private interface behind a firewall or authenticated reverse proxy. Do not publish the API or lab gateway directly to the internet.
- Set `LAB_MODE=false`. This disables lab traffic controls and automated gateway action. The API refuses to start unless `LOGSHIELD_OPERATOR_TOKEN` is at least 24 characters.
- Set a distinct, random ingestion token for each source using `LOGSHIELD_INGEST_TOKENS`. Keep source tokens and the operator token in a secret store or restricted environment file; rotate them after exposure.
- Put TLS and user authentication at a trusted reverse proxy when serving the browser. The proxy must remove any client-supplied `Authorization` header before injecting a **viewer** token for read-only dashboard access. Never inject the operator token into an unaudited browser session. Serve dashboard and API on the same origin; WebSocket upgrades must pass through the proxy. This proxy model remains untested as a complete deployment.
- Allow health checks to `/api/health` without a token. `/api/ingest/events` and `/api/ingest/heartbeat` require a registered source token. Protected GET and WebSocket routes accept `Authorization: Bearer <viewer or operator token>`; writes require the operator token. Browser WebSockets cannot attach arbitrary bearer headers directly, so use the trusted proxy. Never send tokens in query parameters.

## Minimal API configuration

```text
LAB_MODE=false
API_BIND=127.0.0.1:3000
DATABASE_URL=sqlite:///restricted/path/logshield.db?mode=rwc
LOGSHIELD_OPERATOR_TOKEN=<unique random value, at least 24 characters>
LOGSHIELD_VIEWER_TOKEN=<different random value, at least 24 characters, optional>
LOGSHIELD_INGEST_TOKENS={"web-1":"<different random value, at least 24 characters>"}
```

Create the database directory with restrictive permissions and back it up. Do not place real credentials or log contents in Git. Send an event with a stable event ID; the API returns `durable:true` only after SQLite writes the evidence. An HTTP timeout can still mean the write happened, so retry with the same ID. The file agent saves its offset after this receipt. Direct SDK callers can opt into the [bounded disk-backed queue](SDK.md#optional-disk-backed-delivery) and must schedule its flush worker themselves.

## Operational limits

The event correlation pass currently reloads up to 2,000 recent events and recalculates incidents. Only a [synthetic benign ingestion probe](PERFORMANCE.md) has been measured; sustained mixed-traffic throughput and latency remain unknown. Source labels from an application are not verified client IP addresses. There is no multi-tenant isolation, mTLS, key rotation workflow, complete file rotation handling, or high-availability failover. The optional SDK queue is single-owner and has no cross-process coordination or background scheduler. The UI is intended to be accessed through a trusted proxy; never put the operator token in public frontend JavaScript. Run the Docker end-to-end test and review the [evaluation limits](EVALUATION.md) before using real security data.
