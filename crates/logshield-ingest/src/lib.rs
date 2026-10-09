pub use logshield_core::event::{EventType, SecurityEvent};

/// Create a timestamped event. Set the remaining optional fields before sending.
pub fn new_event(event_type: EventType, source: &str, host: &str) -> SecurityEvent {
    SecurityEvent::new(event_type, chrono::Utc::now(), source, host)
}

#[derive(Debug, serde::Deserialize)]
pub struct IngestReceipt {
    pub queued: usize,
    pub source: String,
}

/// Reusable, authenticated Rust client for applications and file agents.
pub struct IngestClient {
    http: reqwest::Client,
    endpoint: String,
    token: String,
}
impl IngestClient {
    pub fn new(endpoint: impl Into<String>, token: impl Into<String>) -> Self {
        Self {
            http: reqwest::Client::new(),
            endpoint: endpoint.into(),
            token: token.into(),
        }
    }
    /// Submit 1–100 events. A receipt means queued by the API, not durably stored yet.
    pub async fn send(&self, events: &[SecurityEvent]) -> Result<IngestReceipt, reqwest::Error> {
        self.http
            .post(format!(
                "{}/api/ingest/events",
                self.endpoint.trim_end_matches('/')
            ))
            .bearer_auth(&self.token)
            .json(&serde_json::json!({"events":events}))
            .send()
            .await?
            .error_for_status()?
            .json()
            .await
    }
    pub async fn heartbeat(&self) -> Result<(), reqwest::Error> {
        self.http
            .post(format!(
                "{}/api/ingest/heartbeat",
                self.endpoint.trim_end_matches('/')
            ))
            .bearer_auth(&self.token)
            .send()
            .await?
            .error_for_status()?;
        Ok(())
    }
}
