use logshield_core::normalizer::parse_line;
use logshield_ingest::IngestClient;
use std::{io::ErrorKind, path::PathBuf};
use tokio::io::{AsyncReadExt, AsyncSeekExt};

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();
    if std::env::args().nth(1).as_deref() == Some("init-demo") {
        let path = PathBuf::from(".env");
        if path.exists() {
            eprintln!(".env already exists; leaving it unchanged");
            return;
        }
        let contents = format!(
            "LOGSHIELD_PG_PASSWORD={}\nLOGSHIELD_INGEST_A={}\nLOGSHIELD_INGEST_B={}\nLOGSHIELD_INGEST_C={}\n",
            uuid::Uuid::new_v4().simple(),
            uuid::Uuid::new_v4().simple(),
            uuid::Uuid::new_v4().simple(),
            uuid::Uuid::new_v4().simple()
        );
        std::fs::write(&path, contents).expect("write local .env");
        println!("Created local .env with generated demo credentials");
        return;
    }
    let endpoint = std::env::var("API_URL").expect("API_URL");
    let token = std::env::var("INGEST_TOKEN").expect("INGEST_TOKEN");
    let source = std::env::var("SOURCE_ID").expect("SOURCE_ID");
    let file = PathBuf::from(std::env::var("LOG_FILE").expect("LOG_FILE"));
    let state = PathBuf::from(std::env::var("STATE_FILE").expect("STATE_FILE"));
    let sdk = IngestClient::new(endpoint, token);
    let mut last_heartbeat = std::time::Instant::now() - std::time::Duration::from_secs(10);
    let mut offset = tokio::fs::read_to_string(&state)
        .await
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(0);
    loop {
        if last_heartbeat.elapsed() >= std::time::Duration::from_secs(5)
            && sdk.heartbeat().await.is_ok()
        {
            last_heartbeat = std::time::Instant::now();
        }
        match read_batch(&file, offset).await {
            Ok((next_offset, lines)) if !lines.is_empty() => {
                let events: Vec<_> = lines
                    .iter()
                    .filter_map(|line| parse_line(line).ok())
                    .collect();
                if events.is_empty() || sdk.send(&events).await.is_ok() {
                    offset = next_offset;
                    if let Some(parent) = state.parent() {
                        let _ = tokio::fs::create_dir_all(parent).await;
                    }
                    if let Err(e) = tokio::fs::write(&state, offset.to_string()).await {
                        tracing::warn!(%e,"offset save failed");
                    }
                    tracing::info!(%source,count=events.len(),"log records submitted");
                }
            }
            Ok(_) => {}
            Err(e) if e.kind() == ErrorKind::NotFound => {}
            Err(e) => tracing::warn!(%e,"log read failed"),
        }
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    }
}
async fn read_batch(path: &PathBuf, offset: u64) -> std::io::Result<(u64, Vec<String>)> {
    let mut file = tokio::fs::File::open(path).await?;
    let len = file.metadata().await?.len();
    let start = if len < offset { 0 } else { offset };
    file.seek(std::io::SeekFrom::Start(start)).await?;
    let mut buf = vec![0; (len - start).min(131_072) as usize];
    let n = file.read(&mut buf).await?;
    buf.truncate(n);
    let Some(last_newline) = buf
        .iter()
        .enumerate()
        .filter(|(_, b)| **b == b'\n')
        .take(100)
        .last()
        .map(|(index, _)| index)
    else {
        return Ok((start, vec![]));
    };
    let consumed = (last_newline + 1) as u64;
    let text = String::from_utf8_lossy(&buf[..=last_newline]);
    Ok((start + consumed, text.lines().map(str::to_owned).collect()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn keeps_partial_line_until_completed() {
        let path = std::env::temp_dir().join(format!("logshield-agent-{}", uuid::Uuid::new_v4()));
        tokio::fs::write(&path, b"first\nsecond").await.unwrap();
        let (offset, lines) = read_batch(&path, 0).await.unwrap();
        assert_eq!(offset, 6);
        assert_eq!(lines, ["first"]);
        let (again, lines) = read_batch(&path, offset).await.unwrap();
        assert_eq!(again, offset);
        assert!(lines.is_empty());
        tokio::fs::write(&path, b"first\nsecond\n").await.unwrap();
        let (offset, lines) = read_batch(&path, offset).await.unwrap();
        assert_eq!(offset, 13);
        assert_eq!(lines, ["second"]);
        tokio::fs::remove_file(path).await.unwrap();
    }

    #[tokio::test]
    async fn limits_batches_to_api_capacity() {
        let path = std::env::temp_dir().join(format!("logshield-agent-{}", uuid::Uuid::new_v4()));
        tokio::fs::write(&path, "line\n".repeat(101)).await.unwrap();
        let (offset, first) = read_batch(&path, 0).await.unwrap();
        assert_eq!(first.len(), 100);
        let (_, second) = read_batch(&path, offset).await.unwrap();
        assert_eq!(second.len(), 1);
        tokio::fs::remove_file(path).await.unwrap();
    }
}
