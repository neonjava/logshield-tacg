use logshield_ingest::{EventType, IngestClient, new_event};

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
    println!("Queued {} event from {}", receipt.queued, receipt.source);
    Ok(())
}
