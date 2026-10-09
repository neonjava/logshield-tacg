# Use LogShield from a Rust application

LogShield's first public integration is a **Git dependency**, not a crates.io release. It accepts normalized security events from trusted applications through an authenticated API. The server performs correlation and scoring; the SDK only submits evidence. The example sends benign local activity.

## 1. Run LogShield privately

Follow the [README](../README.md) to start the isolated Docker lab. Its API is published on `127.0.0.1:3000`. For a private self-hosted deployment, set `LAB_MODE=false`, configure `LOGSHIELD_OPERATOR_TOKEN` (24+ random characters), and keep the API behind a TLS-terminating private reverse proxy. Operator routes require `Authorization: Bearer <operator token>`; authenticated ingestion uses separate source tokens. See [private deployment](DEPLOYMENT.md).

## 2. Register an ingest source

Set `LOGSHIELD_INGEST_TOKENS` on the **LogShield API** to a JSON object mapping a source name to a unique random token of at least 24 characters. The Compose file passes this variable from your local environment. Source names may contain letters, digits, `-`, and `_` (maximum 64 characters). The three existing Docker agent credentials remain supported. The token identifies the submitting application; LogShield stamps its source name into each stored event's `hostname` and `origin` fields, ignoring any claimed origin from the client.

For local development, generate a token with a secure random generator and keep it in an ignored environment file. Example configuration shape (placeholder only):

```text
LOGSHIELD_INGEST_TOKENS={"my-app":"REPLACE_WITH_A_UNIQUE_RANDOM_TOKEN"}
```

Restart the API after changing its environment. Never commit tokens or log files containing personal data.

## 3. Add the Rust dependency

In your own application's `Cargo.toml`:

```toml
[dependencies]
logshield-ingest = { git = "https://github.com/neonjava/logshield-tacg.git" }
tokio = { version = "1", features = ["macros", "rt-multi-thread"] }
```

For a repeatable build, pin `rev` to a reviewed commit hash. Cargo finds `logshield-ingest` inside the repository workspace; no Python service is needed.

## 4. Submit a normal event

```rust
use logshield_ingest::{new_event, EventType, IngestClient};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let endpoint = std::env::var("LOGSHIELD_URL")?;
    let token = std::env::var("LOGSHIELD_TOKEN")?;
    let mut event = new_event(EventType::WebRequest, "normal-client", "my-app");
    event.service = Some("web".into());
    event.action = Some("GET /health".into());
    event.result = Some("success".into());
    event.raw_message = "Example application health request".into();
    let receipt = IngestClient::new(endpoint, token).send(&[event]).await?;
    assert!(receipt.durable, "server did not confirm persistence");
    println!("Stored {} event from {}", receipt.queued, receipt.source);
    Ok(())
}
```

The same source is available as a compilable [example](../crates/logshield-ingest/examples/send_event.rs). With the local API and a registered source running, set `LOGSHIELD_URL=http://127.0.0.1:3000` and `LOGSHIELD_TOKEN` in your terminal, then run `cargo run -p logshield-ingest --example send_event`.

The API accepts **1–100 events per request**, within a **1 MiB request body**. `send` returns an `IngestReceipt` with `queued`, `source`, and `durable`. `durable=true` means the event and incident evidence writes completed in SQLite before the HTTP response. The SDK uses a 15-second request timeout. Keep stable event IDs on retry so SQLite can deduplicate accepted records. `heartbeat()` updates the source's last-seen time. The SDK surfaces HTTP failures through `reqwest::Error`.

### Optional disk-backed delivery

Applications that need to survive a temporary API outage can opt into `DurableIngestQueue`:

```rust
use logshield_ingest::{DurableIngestQueue, IngestClient};

let queue = DurableIngestQueue::new(
    IngestClient::new(endpoint, token),
    "/var/lib/my-app/logshield-spool",
    1_000, // maximum pending batches; each batch holds 1–100 events
)?;
queue.enqueue(&events).await?; // file is synced before this returns
// Call flush periodically, and after connectivity returns.
queue.flush().await?;
```

The queue uses a private directory and private files on Unix, writes each batch with a temporary file and atomic rename, and delivers oldest batches first. It removes a file only after the API confirms `durable:true`. An HTTP timeout can occur after the API commits a batch; stable event IDs make replay idempotent. If the queue is full, `enqueue` fails instead of dropping evidence. Keep the spool directory on durable storage and use **one queue owner per directory**. A corrupt queued file stops flushing for operator repair; there is no automatic corruption recovery, cross-process locking, or built-in background retry scheduler. Call `flush` from your own bounded worker.

## File agent

The included `logshield-agent` tails newline-terminated UTF-8 JSON or supported auth/network log lines from a read-only file. Configure `API_URL`, `INGEST_TOKEN`, `SOURCE_ID`, `LOG_FILE`, and `STATE_FILE`, then run `cargo run -p logshield-ingest --bin logshield-agent`. Keep the state file on durable storage and restrict its permissions. The agent sends batches of at most 100 log lines and advances its offset only after a durable API receipt, then atomically replaces and syncs its offset file. If a line exceeds 128 KiB without a newline, the agent exits with an explicit error for operator repair rather than retrying the same line forever. Robust log rotation, mTLS, key rotation, and a persistent outbound queue remain future work.

## Safety and limits

The SDK does not block traffic or execute log content. Automatic containment remains tied to the local lab gateway and is disabled when `LAB_MODE=false`. Do not treat the current dashboard/API as a production multi-tenant service. Review [architecture](ARCHITECTURE.md) and [evaluation limits](EVALUATION.md) before integrating real security data.
