//! Exercises the actual non-lab Axum server, including WebSocket upgrade auth.
use logshield_ingest::{DurableIngestQueue, EventType, IngestClient, QueueError, new_event};
use reqwest::{Client, StatusCode};
use serde_json::{Value, json};
use std::{
    net::TcpListener,
    path::PathBuf,
    process::{Child, Command, Stdio},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};
use uuid::Uuid;

struct Server {
    child: Child,
}
struct TestDir(PathBuf);
impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
impl Server {
    fn start(port: u16, directory: PathBuf, operator: &str, source: &str) -> Self {
        std::fs::create_dir_all(directory.join("logs")).unwrap();
        let database = format!(
            "sqlite://{}?mode=rwc",
            directory.join("events.db").display()
        );
        let child = Command::new(env!("CARGO_BIN_EXE_logshield-api"))
            .env("LAB_MODE", "false")
            .env("API_BIND", format!("127.0.0.1:{port}"))
            .env("DATABASE_URL", database)
            .env("LOG_DIR", directory.join("logs"))
            .env("LOGSHIELD_OPERATOR_TOKEN", operator)
            .env(
                "LOGSHIELD_INGEST_TOKENS",
                format!(r#"{{"private-app":"{source}"}}"#),
            )
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        Self { child }
    }
}
impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
async fn ready(client: &Client, base: &str) {
    for _ in 0..50 {
        if client
            .get(format!("{base}/api/health"))
            .send()
            .await
            .is_ok_and(|response| response.status() == StatusCode::OK)
        {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("non-lab API did not start");
}
async fn websocket_status(port: u16, token: Option<&str>) -> u16 {
    let mut socket = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let authorization = token
        .map(|value| format!("Authorization: Bearer {value}\r\n"))
        .unwrap_or_default();
    let request = format!(
        "GET /ws/events HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n{authorization}\r\n"
    );
    socket.write_all(request.as_bytes()).await.unwrap();
    let mut buffer = [0_u8; 1024];
    let count = tokio::time::timeout(Duration::from_secs(2), socket.read(&mut buffer))
        .await
        .unwrap()
        .unwrap();
    let response = std::str::from_utf8(&buffer[..count]).unwrap();
    response
        .split_whitespace()
        .nth(1)
        .unwrap()
        .parse::<u16>()
        .unwrap()
}

#[tokio::test]
async fn private_mode_auth_ingest_and_restart() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    let directory = std::env::temp_dir().join(format!("logshield-private-{}", Uuid::new_v4()));
    let _cleanup = TestDir(directory.clone());
    let operator = Uuid::new_v4().simple().to_string();
    let source = Uuid::new_v4().simple().to_string();
    let base = format!("http://127.0.0.1:{port}");
    let client = Client::builder()
        .timeout(Duration::from_secs(3))
        .build()
        .unwrap();
    let server = Server::start(port, directory.clone(), &operator, &source);
    ready(&client, &base).await;

    assert_eq!(
        client
            .get(format!("{base}/api/events"))
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        client
            .get(format!("{base}/api/events"))
            .bearer_auth("wrong")
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );
    let authorized = client
        .get(format!("{base}/api/events"))
        .bearer_auth(&operator)
        .header("Origin", "https://untrusted.example")
        .send()
        .await
        .unwrap();
    assert_eq!(authorized.status(), StatusCode::OK);
    assert!(
        authorized
            .headers()
            .get("access-control-allow-origin")
            .is_none()
    );
    assert_eq!(websocket_status(port, None).await, 401);
    assert_eq!(websocket_status(port, Some(&operator)).await, 101);
    assert_eq!(
        client
            .post(format!("{base}/api/lab/clear"))
            .bearer_auth(&operator)
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::SERVICE_UNAVAILABLE
    );

    let event_id = Uuid::new_v4();
    let payload = json!({"events":[{
        "id":event_id,
        "event_type":"web_request",
        "source_ip":"private-client",
        "destination_ip":null,
        "hostname":"untrusted-claimed-host",
        "username":null,
        "service":"web",
        "port":null,
        "action":"GET /health",
        "result":"success",
        "severity_hint":null,
        "raw_message":"private integration test"
    }]});
    assert_eq!(
        client
            .post(format!("{base}/api/ingest/events"))
            .json(&payload)
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        client
            .post(format!("{base}/api/ingest/events"))
            .bearer_auth(&operator)
            .json(&payload)
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );
    let receipt: Value = client
        .post(format!("{base}/api/ingest/events"))
        .bearer_auth(&source)
        .json(&payload)
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(receipt["durable"], true);
    assert_eq!(receipt["queued"], 1);
    assert_eq!(receipt["source"], "private-app");

    let events: Value = client
        .get(format!("{base}/api/events"))
        .bearer_auth(&operator)
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(events.as_array().unwrap().len(), 1);
    assert_eq!(events[0]["hostname"], "private-app");
    assert_eq!(events[0]["origin"], "agent:private-app");

    drop(server);
    // The database remains available for the restart assertion.
    let server = Server::start(port, directory, &operator, &source);
    ready(&client, &base).await;
    let persisted: Value = client
        .get(format!("{base}/api/events"))
        .bearer_auth(&operator)
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(persisted.as_array().unwrap().len(), 1);
    assert_eq!(persisted[0]["id"], event_id.to_string());
    let retry: Value = client
        .post(format!("{base}/api/ingest/events"))
        .bearer_auth(&source)
        .json(&payload)
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(retry["durable"], true);
    let deduplicated: Value = client
        .get(format!("{base}/api/events"))
        .bearer_auth(&operator)
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(deduplicated.as_array().unwrap().len(), 1);
    drop(server);
}

#[tokio::test]
async fn durable_sdk_queue_replays_after_offline_period() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    let directory = std::env::temp_dir().join(format!("logshield-queue-{}", Uuid::new_v4()));
    let _cleanup = TestDir(directory.clone());
    let operator = Uuid::new_v4().simple().to_string();
    let source = Uuid::new_v4().simple().to_string();
    let base = format!("http://127.0.0.1:{port}");
    let event = new_event(EventType::WebRequest, "client", "claimed-host");
    let queue = DurableIngestQueue::new(
        IngestClient::new(&base, &source),
        directory.join("spool"),
        1,
    )
    .unwrap();
    queue.enqueue(std::slice::from_ref(&event)).await.unwrap();
    assert!(matches!(
        queue.enqueue(std::slice::from_ref(&event)).await,
        Err(QueueError::Full)
    ));
    assert!(matches!(queue.flush().await, Err(QueueError::Delivery(_))));
    assert_eq!(queue.pending_batches().await.unwrap(), 1);
    drop(queue);

    let queue = DurableIngestQueue::new(
        IngestClient::new(&base, &source),
        directory.join("spool"),
        1,
    )
    .unwrap();
    assert_eq!(queue.pending_batches().await.unwrap(), 1);
    let server = Server::start(port, directory.clone(), &operator, &source);
    let client = Client::new();
    ready(&client, &base).await;
    assert_eq!(queue.flush().await.unwrap(), 1);
    assert_eq!(queue.pending_batches().await.unwrap(), 0);
    let events: Value = client
        .get(format!("{base}/api/events"))
        .bearer_auth(&operator)
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(events.as_array().unwrap().len(), 1);
    assert_eq!(events[0]["id"], event.id.to_string());
    drop(server);
}

#[tokio::test]
#[ignore = "manual synthetic ingest measurement; use --ignored --nocapture"]
async fn synthetic_private_ingest_throughput() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    let directory = std::env::temp_dir().join(format!("logshield-load-{}", Uuid::new_v4()));
    let _cleanup = TestDir(directory.clone());
    let operator = Uuid::new_v4().simple().to_string();
    let source = Uuid::new_v4().simple().to_string();
    let base = format!("http://127.0.0.1:{port}");
    let server = Server::start(port, directory.clone(), &operator, &source);
    ready(&Client::new(), &base).await;
    let sdk = IngestClient::new(&base, &source);
    let start = std::time::Instant::now();
    let mut latencies = Vec::new();
    for _ in 0..50 {
        let batch: Vec<_> = (0..100)
            .map(|_| new_event(EventType::WebRequest, "load-client", "private-app"))
            .collect();
        let sent = std::time::Instant::now();
        let receipt = sdk.send(&batch).await.unwrap();
        assert!(receipt.durable);
        latencies.push(sent.elapsed().as_secs_f64() * 1_000.0);
    }
    let seconds = start.elapsed().as_secs_f64();
    latencies.sort_by(f64::total_cmp);
    let database = format!("sqlite://{}", directory.join("events.db").display());
    let pool = sqlx::SqlitePool::connect(&database).await.unwrap();
    let persisted: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM events")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(persisted, 5_000);
    println!(
        "synthetic localhost ingest: {persisted} events in {seconds:.2}s ({:.0} events/s), batch p50 {:.1}ms, p95 {:.1}ms; sequential 100-event batches, single API process, SQLite, no attack mix",
        persisted as f64 / seconds,
        latencies[24],
        latencies[47],
    );
    pool.close().await;
    drop(server);
}
