use logshield_core::event::SecurityEvent;

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
    pub async fn send(
        &self,
        events: &[SecurityEvent],
    ) -> Result<serde_json::Value, reqwest::Error> {
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
