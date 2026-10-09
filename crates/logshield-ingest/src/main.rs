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
                let accepted = if events.is_empty() {
                    true
                } else {
                    match sdk.send(&events).await {
                        Ok(receipt) if receipt.durable && receipt.queued == events.len() => true,
                        Ok(receipt) => {
                            tracing::warn!(?receipt, "ingest acknowledgement was not durable");
                            false
                        }
                        Err(e) => {
                            tracing::warn!(%e, "log submission failed; retaining offset for retry");
                            false
                        }
                    }
                };
                if accepted {
                    match save_offset(&state, next_offset).await {
                        Ok(()) => {
                            offset = next_offset;
                            tracing::info!(%source,count=events.len(),"log records submitted");
                        }
                        Err(e) => tracing::error!(%e, "offset save failed; batch will be retried"),
                    }
                }
            }
            Ok(_) => {}
            Err(e) if e.kind() == ErrorKind::NotFound => {}
            Err(e) if e.kind() == ErrorKind::InvalidData => {
                tracing::error!(%e,"log record exceeds the 128 KiB limit; agent stopped so the operator can repair the source");
                std::process::exit(1);
            }
            Err(e) => tracing::warn!(%e,"log read failed"),
        }
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    }
}
async fn save_offset(path: &PathBuf, offset: u64) -> std::io::Result<()> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        tokio::fs::create_dir_all(parent).await?;
    }
    let temporary = path.with_extension(format!("{}.tmp", std::process::id()));
    let mut file = tokio::fs::File::create(&temporary).await?;
    use tokio::io::AsyncWriteExt;
    file.write_all(offset.to_string().as_bytes()).await?;
    file.sync_all().await?;
    drop(file);
    tokio::fs::rename(&temporary, path).await?;
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        std::fs::File::open(parent)?.sync_all()?;
    }
    Ok(())
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
        if n == 131_072 {
            return Err(std::io::Error::new(
                ErrorKind::InvalidData,
                format!("oversized log line at byte offset {start}"),
            ));
        }
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

    #[tokio::test]
    async fn oversized_line_is_reported_instead_of_stalling() {
        let path = std::env::temp_dir().join(format!("logshield-agent-{}", uuid::Uuid::new_v4()));
        tokio::fs::write(&path, vec![b'x'; 131_073]).await.unwrap();
        let error = read_batch(&path, 0).await.unwrap_err();
        assert_eq!(error.kind(), ErrorKind::InvalidData);
        tokio::fs::remove_file(path).await.unwrap();
    }

    #[tokio::test]
    async fn offset_is_replaced_after_sync() {
        let path = std::env::temp_dir().join(format!("logshield-offset-{}", uuid::Uuid::new_v4()));
        save_offset(&path, 18).await.unwrap();
        assert_eq!(tokio::fs::read_to_string(&path).await.unwrap(), "18");
        save_offset(&path, 42).await.unwrap();
        assert_eq!(tokio::fs::read_to_string(&path).await.unwrap(), "42");
        tokio::fs::remove_file(path).await.unwrap();
    }
}
