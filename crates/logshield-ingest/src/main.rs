use logshield_core::normalizer::parse_line;
use logshield_ingest::IngestClient;
use serde::{Deserialize, Serialize};
use std::os::unix::fs::MetadataExt;
use std::{io::ErrorKind, path::PathBuf};
use tokio::io::{AsyncReadExt, AsyncSeekExt};

#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
struct Cursor {
    offset: u64,
    device: u64,
    inode: u64,
}

fn parse_cursor(contents: &str) -> Cursor {
    serde_json::from_str(contents).unwrap_or_else(|_| Cursor {
        offset: contents.trim().parse().unwrap_or(0),
        ..Cursor::default()
    })
}

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
    let mut cursor = tokio::fs::read_to_string(&state)
        .await
        .ok()
        .map(|contents| parse_cursor(&contents))
        .unwrap_or_default();
    loop {
        if last_heartbeat.elapsed() >= std::time::Duration::from_secs(5)
            && sdk.heartbeat().await.is_ok()
        {
            last_heartbeat = std::time::Instant::now();
        }
        match read_batch(&file, cursor).await {
            Ok((next_cursor, lines)) if !lines.is_empty() => {
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
                    match save_cursor(&state, next_cursor).await {
                        Ok(()) => {
                            cursor = next_cursor;
                            tracing::info!(%source,count=events.len(),"log records submitted");
                        }
                        Err(e) => tracing::error!(%e, "offset save failed; batch will be retried"),
                    }
                }
            }
            Ok((next_cursor, _)) if next_cursor != cursor => {
                // A truncated or rotated empty file must still replace the old cursor.
                if let Err(error) = save_cursor(&state, next_cursor).await {
                    tracing::error!(%error, "cursor save failed after file rotation");
                } else {
                    cursor = next_cursor;
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
async fn save_cursor(path: &PathBuf, cursor: Cursor) -> std::io::Result<()> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        tokio::fs::create_dir_all(parent).await?;
    }
    let temporary = path.with_extension(format!("{}.tmp", std::process::id()));
    let mut file = tokio::fs::File::create(&temporary).await?;
    use tokio::io::AsyncWriteExt;
    file.write_all(serde_json::to_string(&cursor).unwrap().as_bytes())
        .await?;
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
async fn read_batch(path: &PathBuf, cursor: Cursor) -> std::io::Result<(Cursor, Vec<String>)> {
    let mut file = tokio::fs::File::open(path).await?;
    let metadata = file.metadata().await?;
    let len = metadata.len();
    let identity = Cursor {
        offset: 0,
        device: metadata.dev(),
        inode: metadata.ino(),
    };
    let start = if (cursor.inode != 0
        && (cursor.inode != identity.inode || cursor.device != identity.device))
        || len < cursor.offset
    {
        0
    } else {
        cursor.offset
    };
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
        return Ok((
            Cursor {
                offset: start,
                ..identity
            },
            vec![],
        ));
    };
    let consumed = (last_newline + 1) as u64;
    let text = String::from_utf8_lossy(&buf[..=last_newline]);
    Ok((
        Cursor {
            offset: start + consumed,
            ..identity
        },
        text.lines().map(str::to_owned).collect(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn keeps_partial_line_until_completed() {
        let path = std::env::temp_dir().join(format!("logshield-agent-{}", uuid::Uuid::new_v4()));
        tokio::fs::write(&path, b"first\nsecond").await.unwrap();
        let (offset, lines) = read_batch(&path, Cursor::default()).await.unwrap();
        assert_eq!(offset.offset, 6);
        assert_eq!(lines, ["first"]);
        let (again, lines) = read_batch(&path, offset).await.unwrap();
        assert_eq!(again, offset);
        assert!(lines.is_empty());
        tokio::fs::write(&path, b"first\nsecond\n").await.unwrap();
        let (offset, lines) = read_batch(&path, offset).await.unwrap();
        assert_eq!(offset.offset, 13);
        assert_eq!(lines, ["second"]);
        tokio::fs::remove_file(path).await.unwrap();
    }

    #[tokio::test]
    async fn limits_batches_to_api_capacity() {
        let path = std::env::temp_dir().join(format!("logshield-agent-{}", uuid::Uuid::new_v4()));
        tokio::fs::write(&path, "line\n".repeat(101)).await.unwrap();
        let (offset, first) = read_batch(&path, Cursor::default()).await.unwrap();
        assert_eq!(first.len(), 100);
        let (_, second) = read_batch(&path, offset).await.unwrap();
        assert_eq!(second.len(), 1);
        tokio::fs::remove_file(path).await.unwrap();
    }

    #[tokio::test]
    async fn oversized_line_is_reported_instead_of_stalling() {
        let path = std::env::temp_dir().join(format!("logshield-agent-{}", uuid::Uuid::new_v4()));
        tokio::fs::write(&path, vec![b'x'; 131_073]).await.unwrap();
        let error = read_batch(&path, Cursor::default()).await.unwrap_err();
        assert_eq!(error.kind(), ErrorKind::InvalidData);
        tokio::fs::remove_file(path).await.unwrap();
    }

    #[tokio::test]
    async fn offset_is_replaced_after_sync() {
        let path = std::env::temp_dir().join(format!("logshield-offset-{}", uuid::Uuid::new_v4()));
        let first = Cursor {
            offset: 18,
            device: 4,
            inode: 5,
        };
        save_cursor(&path, first).await.unwrap();
        assert_eq!(
            parse_cursor(&tokio::fs::read_to_string(&path).await.unwrap()),
            first
        );
        let second = Cursor {
            offset: 42,
            ..first
        };
        save_cursor(&path, second).await.unwrap();
        assert_eq!(
            parse_cursor(&tokio::fs::read_to_string(&path).await.unwrap()),
            second
        );
        assert_eq!(
            parse_cursor("18").offset,
            18,
            "legacy numeric offsets remain readable"
        );
        tokio::fs::remove_file(path).await.unwrap();
    }

    #[tokio::test]
    async fn rotation_with_larger_new_file_starts_at_zero_after_restart() {
        let path =
            std::env::temp_dir().join(format!("logshield-rotation-{}", uuid::Uuid::new_v4()));
        let old = path.with_extension("old");
        let state = path.with_extension("state");
        tokio::fs::write(&path, b"old-record\n").await.unwrap();
        let (cursor, lines) = read_batch(&path, Cursor::default()).await.unwrap();
        assert_eq!(lines, ["old-record"]);
        save_cursor(&state, cursor).await.unwrap();
        tokio::fs::rename(&path, &old).await.unwrap();
        tokio::fs::write(&path, b"new-record-one\nnew-record-two\n")
            .await
            .unwrap();
        let restarted = parse_cursor(&tokio::fs::read_to_string(&state).await.unwrap());
        let (next, lines) = read_batch(&path, restarted).await.unwrap();
        assert_eq!(lines, ["new-record-one", "new-record-two"]);
        assert_ne!(next.inode, restarted.inode);
        for file in [path, old, state] {
            tokio::fs::remove_file(file).await.unwrap();
        }
    }
}
