use crate::{IngestClient, SecurityEvent};
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Write},
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::sync::Mutex;
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
    guard: Mutex<()>,
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
            guard: Mutex::new(()),
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
        let _guard = self.guard.lock().await;
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
        let _guard = self.guard.lock().await;
        Ok(pending_files(&self.directory)?.len())
    }

    /// Deliver oldest batches first. Any failed batch stays on disk for a later retry.
    pub async fn flush(&self) -> Result<usize, QueueError> {
        let _guard = self.guard.lock().await;
        let mut delivered = 0;
        for path in pending_files(&self.directory)? {
            let events: Vec<SecurityEvent> = serde_json::from_slice(&fs::read(&path)?)?;
            let receipt = self.client.send(&events).await?;
            if !receipt.durable || receipt.queued != events.len() {
                return Err(QueueError::MissingDurableReceipt);
            }
            fs::remove_file(path)?;
            sync_directory(&self.directory)?;
            delivered += 1;
        }
        Ok(delivered)
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
