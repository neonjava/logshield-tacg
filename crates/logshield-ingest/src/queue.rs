use crate::{IngestClient, SecurityEvent};
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Write},
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::sync::{Mutex, watch};
use uuid::Uuid;

#[derive(Debug, thiserror::Error)]
pub enum QueueError {
    #[error("queue I/O failed: {0}")]
    Io(#[from] io::Error),
    #[error("queue serialization failed: {0}")]
    Json(#[from] serde_json::Error),
    #[error("delivery failed; batch remains queued: {0}")]
    Delivery(#[from] reqwest::Error),
    #[error("batch must contain 1–100 events and fit within 1 MiB")]
    InvalidBatch,
    #[error("queue is full; batch was not accepted")]
    Full,
    #[error("server did not confirm durable storage; batch remains queued")]
    MissingDurableReceipt,
}

/// Single-process, bounded disk spool for applications that need retryable SDK delivery.
/// Preserve this directory across restarts and call `flush` periodically.
pub struct DurableIngestQueue {
    client: IngestClient,
    directory: PathBuf,
    max_pending_batches: usize,
    io_guard: Mutex<()>,
    flush_guard: Mutex<()>,
}
impl DurableIngestQueue {
    pub fn new(
        client: IngestClient,
        directory: impl Into<PathBuf>,
        max_pending_batches: usize,
    ) -> Result<Self, QueueError> {
        if max_pending_batches == 0 {
            return Err(QueueError::Full);
        }
        let directory = directory.into();
        fs::create_dir_all(&directory)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))?;
        }
        Ok(Self {
            client,
            directory,
            max_pending_batches,
            io_guard: Mutex::new(()),
            flush_guard: Mutex::new(()),
        })
    }

    /// Persist a batch before attempting network delivery. Returns its spool ID.
    pub async fn enqueue(&self, events: &[SecurityEvent]) -> Result<Uuid, QueueError> {
        if events.is_empty() || events.len() > 100 {
            return Err(QueueError::InvalidBatch);
        }
        let payload = serde_json::to_vec(events)?;
        if payload.len() > 1_000_000 {
            return Err(QueueError::InvalidBatch);
        }
        let _guard = self.io_guard.lock().await;
        if pending_files(&self.directory)?.len() >= self.max_pending_batches {
            return Err(QueueError::Full);
        }
        let id = Uuid::new_v4();
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(io::Error::other)?
            .as_nanos();
        let basename = format!("{nanos:020}-{id}");
        let temporary = self.directory.join(format!("{basename}.tmp"));
        let committed = self.directory.join(format!("{basename}.json"));
        let mut file = private_file(&temporary)?;
        file.write_all(&payload)?;
        file.sync_all()?;
        drop(file);
        fs::rename(&temporary, &committed)?;
        sync_directory(&self.directory)?;
        Ok(id)
    }

    pub async fn pending_batches(&self) -> Result<usize, QueueError> {
        let _guard = self.io_guard.lock().await;
        Ok(pending_files(&self.directory)?.len())
    }

    /// Deliver oldest batches first. Any failed batch stays on disk for a later retry.
    pub async fn flush(&self) -> Result<usize, QueueError> {
        let _flush = self.flush_guard.lock().await;
        let files = {
            let _io = self.io_guard.lock().await;
            pending_files(&self.directory)?
        };
        let mut delivered = 0;
        for path in files {
            let events: Vec<SecurityEvent> = {
                let _io = self.io_guard.lock().await;
                serde_json::from_slice(&fs::read(&path)?)?
            };
            let receipt = self.client.send(&events).await?;
            if !receipt.durable || receipt.queued != events.len() {
                return Err(QueueError::MissingDurableReceipt);
            }
            let _io = self.io_guard.lock().await;
            fs::remove_file(path)?;
            sync_directory(&self.directory)?;
            delivered += 1;
        }
        Ok(delivered)
    }

    /// Retry pending batches on startup and at each interval until shutdown.
    /// Errors keep data on disk and are logged; the next interval retries them.
    pub async fn run_until_cancelled(
        &self,
        interval: std::time::Duration,
        mut shutdown: watch::Receiver<bool>,
    ) {
        let interval = interval.max(std::time::Duration::from_millis(100));
        loop {
            if *shutdown.borrow() {
                return;
            }
            tokio::select! {
                result = self.flush() => {
                    if let Err(error) = result {
                        tracing::warn!(%error, "queued LogShield delivery will be retried");
                    }
                }
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() { return; }
                }
            }
            tokio::select! {
                _ = tokio::time::sleep(interval) => {},
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() { return; }
                }
            }
        }
    }
}
fn pending_files(directory: &Path) -> io::Result<Vec<PathBuf>> {
    let mut files = fs::read_dir(directory)?
        .map(|entry| entry.map(|entry| entry.path()))
        .collect::<io::Result<Vec<_>>>()?;
    files.retain(|path| {
        path.extension()
            .is_some_and(|extension| extension == "json")
    });
    files.sort();
    Ok(files)
}
fn private_file(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path)
}
fn sync_directory(directory: &Path) -> io::Result<()> {
    File::open(directory)?.sync_all()
}
