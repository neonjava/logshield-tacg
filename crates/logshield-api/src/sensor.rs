use crate::WorkItem;
use logshield_core::normalizer::parse_line;
use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};
use tokio::{
    io::{AsyncReadExt, AsyncSeekExt},
    sync::{Mutex, mpsc},
};

pub type Offsets = Arc<Mutex<HashMap<PathBuf, (u64, Vec<u8>)>>>;
const FILES: [&str; 4] = ["app-a.log", "app-b.log", "app-c.log", "gateway.log"];

pub async fn start(
    dir: PathBuf,
    tx: mpsc::Sender<WorkItem>,
    online: Arc<AtomicBool>,
    offsets: Offsets,
) {
    loop {
        online.store(dir.is_dir(), Ordering::Relaxed);
        for name in FILES {
            let path = dir.join(name);
            match read_new(&path, &offsets).await {
                Ok(lines) => {
                    for line in lines {
                        if let Ok(text) = std::str::from_utf8(&line) {
                            match parse_line(text) {
                                Ok(mut event) => {
                                    event.origin = Some("lab_sensor".into());
                                    if tx.send(WorkItem::background(vec![event])).await.is_err() {
                                        return;
                                    }
                                }
                                Err(e) => tracing::warn!(file=%name,%e,"invalid log line"),
                            }
                        }
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => tracing::warn!(file=%name,%e,"sensor read failed"),
            }
        }
        tokio::time::sleep(std::time::Duration::from_millis(150)).await;
    }
}
async fn read_new(path: &Path, offsets: &Offsets) -> std::io::Result<Vec<Vec<u8>>> {
    let mut f = tokio::fs::File::open(path).await?;
    let len = f.metadata().await?.len();
    let mut guard = offsets.lock().await;
    let (offset, partial) = guard.entry(path.to_path_buf()).or_insert((0, Vec::new()));
    if len < *offset {
        *offset = 0;
        partial.clear();
    }
    f.seek(std::io::SeekFrom::Start(*offset)).await?;
    let max = (len - *offset).min(1_048_576) as usize;
    let mut buf = vec![0u8; max];
    let n = f.read(&mut buf).await?;
    buf.truncate(n);
    *offset += n as u64;
    partial.extend(buf);
    if partial.len() > 1_048_576 {
        partial.clear();
        return Ok(vec![]);
    }
    let mut lines = Vec::new();
    while let Some(pos) = partial.iter().position(|b| *b == b'\n') {
        let line = partial.drain(..=pos).collect::<Vec<_>>();
        if line.len() <= 16_384 {
            lines.push(line[..line.len() - 1].to_vec());
        }
    }
    Ok(lines)
}
pub async fn skip_existing(dir: &Path, offsets: &Offsets) {
    let mut guard = offsets.lock().await;
    for name in FILES {
        let path = dir.join(name);
        if let Ok(meta) = tokio::fs::metadata(&path).await {
            guard.insert(path, (meta.len(), Vec::new()));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;
    #[tokio::test]
    async fn follows_complete_lines_and_handles_truncation() {
        let path =
            std::env::temp_dir().join(format!("logshield-sensor-{}.log", uuid::Uuid::new_v4()));
        let offsets = Offsets::default();
        tokio::fs::write(&path, b"first").await.unwrap();
        assert!(read_new(&path, &offsets).await.unwrap().is_empty());
        let mut file = tokio::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .await
            .unwrap();
        file.write_all(b"\nsecond\n").await.unwrap();
        file.flush().await.unwrap();
        let lines = read_new(&path, &offsets).await.unwrap();
        assert_eq!(lines, vec![b"first".to_vec(), b"second".to_vec()]);
        tokio::fs::write(&path, b"new\n").await.unwrap();
        let lines = read_new(&path, &offsets).await.unwrap();
        assert_eq!(lines, vec![b"new".to_vec()]);
        tokio::fs::remove_file(path).await.unwrap();
    }
}
