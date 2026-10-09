use logshield_core::{
    baseline::{Baseline, BaselineSnapshot},
    event::{EventType, SecurityEvent},
    incident::Incident,
};
use sqlx::{Row, SqlitePool};

pub async fn init(db: &SqlitePool) -> Result<(), sqlx::Error> {
    for query in [
        "CREATE TABLE IF NOT EXISTS events(id TEXT PRIMARY KEY,timestamp TEXT NOT NULL,source_ip TEXT,payload TEXT NOT NULL)",
        "CREATE TABLE IF NOT EXISTS entities(kind TEXT NOT NULL,value TEXT NOT NULL,first_seen TEXT NOT NULL,last_seen TEXT NOT NULL,event_count INTEGER NOT NULL DEFAULT 0,PRIMARY KEY(kind,value))",
        "CREATE TABLE IF NOT EXISTS incidents(id TEXT PRIMARY KEY,source_ip TEXT,risk INTEGER NOT NULL,payload TEXT NOT NULL)",
        "CREATE TABLE IF NOT EXISTS incident_events(incident_id TEXT NOT NULL,event_id TEXT NOT NULL,PRIMARY KEY(incident_id,event_id))",
        "CREATE TABLE IF NOT EXISTS correlation_edges(incident_id TEXT NOT NULL,from_id TEXT NOT NULL,to_id TEXT NOT NULL,strength REAL NOT NULL,reasons TEXT NOT NULL,PRIMARY KEY(incident_id,from_id,to_id))",
        "CREATE TABLE IF NOT EXISTS responses(incident_id TEXT PRIMARY KEY,status TEXT NOT NULL,payload TEXT NOT NULL)",
        "CREATE TABLE IF NOT EXISTS verification_attempts(id TEXT PRIMARY KEY,incident_id TEXT NOT NULL,timestamp TEXT NOT NULL,http_status INTEGER NOT NULL,blocked INTEGER NOT NULL,matched INTEGER NOT NULL,payload TEXT NOT NULL)",
        "CREATE TABLE IF NOT EXISTS gateway_blocks(incident_id TEXT PRIMARY KEY,source TEXT NOT NULL,expires_at TEXT NOT NULL,payload TEXT NOT NULL)",
        "CREATE TABLE IF NOT EXISTS source_heartbeats(source TEXT PRIMARY KEY, seen_at TEXT NOT NULL)",
        "CREATE TABLE IF NOT EXISTS baseline_candidates(event_id TEXT PRIMARY KEY,username TEXT NOT NULL,source_ip TEXT NOT NULL,hostname TEXT NOT NULL,observed_at TEXT NOT NULL,event_ts TEXT NOT NULL)",
        "CREATE INDEX IF NOT EXISTS baseline_candidates_lookup ON baseline_candidates(username,source_ip,hostname,observed_at)",
        "CREATE TABLE IF NOT EXISTS baseline_snapshots(version INTEGER PRIMARY KEY,payload TEXT NOT NULL,approved_at TEXT NOT NULL)",
        "CREATE INDEX IF NOT EXISTS events_timestamp_idx ON events(timestamp DESC)",
    ] {
        sqlx::query(query).execute(db).await?;
    }
    Ok(())
}
pub async fn insert_event(db: &SqlitePool, e: &SecurityEvent) -> Result<bool, sqlx::Error> {
    let mut tx = db.begin().await?;
    let result =
        sqlx::query("INSERT OR IGNORE INTO events(id,timestamp,source_ip,payload) VALUES(?,?,?,?)")
            .bind(e.id.to_string())
            .bind(e.timestamp.to_rfc3339())
            .bind(&e.source_ip)
            .bind(serde_json::to_string(e).unwrap())
            .execute(&mut *tx)
            .await?;
    if result.rows_affected() == 0 {
        return Ok(false);
    }
    for (kind, value) in [
        ("source", &e.source_ip),
        ("destination", &e.destination_ip),
        ("host", &e.hostname),
        ("user", &e.username),
        ("service", &e.service),
    ] {
        if let Some(value) = value {
            sqlx::query("INSERT INTO entities(kind,value,first_seen,last_seen,event_count) VALUES(?,?,?,?,1) ON CONFLICT(kind,value) DO UPDATE SET last_seen=excluded.last_seen,event_count=event_count+1").bind(kind).bind(value).bind(e.timestamp.to_rfc3339()).bind(e.timestamp.to_rfc3339()).execute(&mut *tx).await?;
        }
    }
    if e.event_type == EventType::SuccessfulLogin
        && e.origin
            .as_deref()
            .is_some_and(|origin| origin.starts_with("agent:"))
        && e.timestamp <= chrono::Utc::now() + chrono::Duration::seconds(60)
        && e.timestamp >= chrono::Utc::now() - chrono::Duration::days(30)
        && let (Some(user), Some(ip), Some(host)) = (&e.username, &e.source_ip, &e.hostname)
    {
        sqlx::query("INSERT OR IGNORE INTO baseline_candidates(event_id,username,source_ip,hostname,observed_at,event_ts) VALUES(?,?,?,?,?,?)")
            .bind(e.id.to_string()).bind(user).bind(ip).bind(host)
            .bind(chrono::Utc::now().to_rfc3339()).bind(e.timestamp.to_rfc3339())
            .execute(&mut *tx).await?;
    }
    tx.commit().await?;
    Ok(true)
}
pub async fn baseline(db: &SqlitePool) -> Result<Baseline, String> {
    let row = sqlx::query("SELECT payload FROM baseline_snapshots ORDER BY version DESC LIMIT 1")
        .fetch_optional(db)
        .await
        .map_err(|e| e.to_string())?;
    let Some(row) = row else {
        return Ok(Baseline::default());
    };
    let snapshot: BaselineSnapshot = serde_json::from_str(&row.get::<String, _>("payload"))
        .map_err(|e| format!("invalid persisted baseline snapshot: {e}"))?;
    let mut baseline = Baseline::default();
    baseline.restore_snapshot(snapshot);
    Ok(baseline)
}

pub async fn approve_baseline(
    db: &SqlitePool,
    user: &str,
    ip: &str,
    host: &str,
) -> Result<Baseline, String> {
    let now = chrono::Utc::now();
    let rows = sqlx::query("SELECT c.observed_at,c.event_ts FROM baseline_candidates c WHERE c.username=? AND c.source_ip=? AND c.hostname=? AND NOT EXISTS (SELECT 1 FROM incident_events i WHERE i.event_id=c.event_id) ORDER BY c.observed_at")
        .bind(user).bind(ip).bind(host).fetch_all(db).await.map_err(|e| e.to_string())?;
    let mut baseline = baseline(db).await?;
    for row in rows {
        let seen = chrono::DateTime::parse_from_rfc3339(row.get::<&str, _>("observed_at"))
            .map_err(|e| e.to_string())?
            .with_timezone(&chrono::Utc);
        let event_ts = chrono::DateTime::parse_from_rfc3339(row.get::<&str, _>("event_ts"))
            .map_err(|e| e.to_string())?
            .with_timezone(&chrono::Utc);
        if event_ts <= now - chrono::Duration::seconds(600) {
            baseline.record_quarantine_observation(user, Some(ip), Some(host), seen);
        }
    }
    if !baseline.approve_quarantined(user, ip, host, now) {
        return Err("candidate needs three distinct, incident-free agent logins, a 10-minute event boundary, and one hour of quarantine".into());
    }
    let snapshot = baseline.snapshot();
    sqlx::query("INSERT INTO baseline_snapshots(version,payload,approved_at) VALUES(?,?,?)")
        .bind(snapshot.version as i64)
        .bind(serde_json::to_string(&snapshot).map_err(|e| e.to_string())?)
        .bind(now.to_rfc3339())
        .execute(db)
        .await
        .map_err(|e| e.to_string())?;
    Ok(baseline)
}
pub async fn events(db: &SqlitePool) -> Result<Vec<SecurityEvent>, sqlx::Error> {
    let rows = sqlx::query("SELECT payload FROM events ORDER BY timestamp DESC LIMIT 2000")
        .fetch_all(db)
        .await?;
    Ok(rows
        .iter()
        .filter_map(|r| serde_json::from_str(&r.get::<String, _>("payload")).ok())
        .collect())
}
pub async fn incidents(db: &SqlitePool) -> Result<Vec<Incident>, sqlx::Error> {
    let rows = sqlx::query("SELECT payload FROM incidents ORDER BY risk DESC, rowid DESC")
        .fetch_all(db)
        .await?;
    Ok(rows
        .iter()
        .filter_map(|r| serde_json::from_str(&r.get::<String, _>("payload")).ok())
        .collect())
}
pub async fn incident(db: &SqlitePool, id: &str) -> Result<Option<Incident>, sqlx::Error> {
    let row = sqlx::query("SELECT payload FROM incidents WHERE id=?")
        .bind(id)
        .fetch_optional(db)
        .await?;
    Ok(row.and_then(|r| serde_json::from_str(&r.get::<String, _>("payload")).ok()))
}
pub async fn save_incident(db: &SqlitePool, i: &Incident) -> Result<(), sqlx::Error> {
    let mut tx = db.begin().await?;
    sqlx::query("INSERT INTO incidents(id,source_ip,risk,payload) VALUES(?,?,?,?) ON CONFLICT(id) DO UPDATE SET risk=excluded.risk,payload=excluded.payload").bind(i.id.to_string()).bind(&i.source_ip).bind(i.risk as i64).bind(serde_json::to_string(i).unwrap()).execute(&mut *tx).await?;
    sqlx::query("DELETE FROM incident_events WHERE incident_id=?")
        .bind(i.id.to_string())
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM correlation_edges WHERE incident_id=?")
        .bind(i.id.to_string())
        .execute(&mut *tx)
        .await?;
    for e in &i.events {
        sqlx::query("INSERT INTO incident_events(incident_id,event_id) VALUES(?,?)")
            .bind(i.id.to_string())
            .bind(e.id.to_string())
            .execute(&mut *tx)
            .await?;
    }
    for edge in &i.edges {
        sqlx::query("INSERT INTO correlation_edges(incident_id,from_id,to_id,strength,reasons) VALUES(?,?,?,?,?)").bind(i.id.to_string()).bind(edge.from.to_string()).bind(edge.to.to_string()).bind(edge.strength).bind(serde_json::to_string(&edge.reasons).unwrap()).execute(&mut *tx).await?;
    }
    if let Some(r) = &i.response {
        sqlx::query("INSERT INTO responses(incident_id,status,payload) VALUES(?,?,?) ON CONFLICT(incident_id) DO UPDATE SET status=excluded.status,payload=excluded.payload").bind(i.id.to_string()).bind(format!("{:?}",i.status)).bind(serde_json::to_string(r).unwrap()).execute(&mut *tx).await?;
    }
    tx.commit().await?;
    Ok(())
}
pub async fn clear(db: &SqlitePool) -> Result<(), sqlx::Error> {
    let mut tx = db.begin().await?;
    for table in [
        "verification_attempts",
        "gateway_blocks",
        "responses",
        "correlation_edges",
        "incident_events",
        "incidents",
        "entities",
        "events",
        "source_heartbeats",
    ] {
        sqlx::query(&format!("DELETE FROM {table}"))
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await?;
    Ok(())
}

#[cfg(test)]
mod baseline_tests {
    use super::*;
    use chrono::{Duration, Utc};
    use sqlx::sqlite::SqlitePoolOptions;

    #[tokio::test]
    async fn reviewed_baseline_survives_restart_and_retries_do_not_count_twice() {
        let path =
            std::env::temp_dir().join(format!("logshield-baseline-{}.db", uuid::Uuid::new_v4()));
        let url = format!("sqlite://{}?mode=rwc", path.display());
        let db = SqlitePoolOptions::new()
            .max_connections(1)
            .connect(&url)
            .await
            .unwrap();
        init(&db).await.unwrap();
        for _ in 0..3 {
            let mut event = SecurityEvent::new(
                EventType::SuccessfulLogin,
                Utc::now() - Duration::hours(2),
                "192.0.2.9",
                "app-a",
            );
            event.username = Some("alice".into());
            event.origin = Some("agent:app-a".into());
            assert!(insert_event(&db, &event).await.unwrap());
            assert!(!insert_event(&db, &event).await.unwrap());
        }
        assert!(
            approve_baseline(&db, "alice", "192.0.2.9", "app-a")
                .await
                .is_err()
        );
        sqlx::query("UPDATE baseline_candidates SET observed_at=?")
            .bind((Utc::now() - Duration::hours(2)).to_rfc3339())
            .execute(&db)
            .await
            .unwrap();
        let approved = approve_baseline(&db, "alice", "192.0.2.9", "app-a")
            .await
            .unwrap();
        assert!(approved.users["alice"].source_ips.contains("192.0.2.9"));
        assert!(
            approve_baseline(&db, "alice", "192.0.2.9", "app-a")
                .await
                .is_err()
        );
        db.close().await;
        let reopened = SqlitePoolOptions::new()
            .max_connections(1)
            .connect(&url)
            .await
            .unwrap();
        let restored = baseline(&reopened).await.unwrap();
        assert!(restored.users["alice"].source_ips.contains("192.0.2.9"));
        reopened.close().await;
        std::fs::remove_file(path).unwrap();
    }
}
