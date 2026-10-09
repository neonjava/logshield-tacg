use logshield_core::{event::SecurityEvent, incident::Incident};
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
    ] {
        sqlx::query(query).execute(db).await?;
    }
    Ok(())
}
pub async fn insert_event(db: &SqlitePool, e: &SecurityEvent) -> Result<bool, sqlx::Error> {
    let result =
        sqlx::query("INSERT OR IGNORE INTO events(id,timestamp,source_ip,payload) VALUES(?,?,?,?)")
            .bind(e.id.to_string())
            .bind(e.timestamp.to_rfc3339())
            .bind(&e.source_ip)
            .bind(serde_json::to_string(e).unwrap())
            .execute(db)
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
            sqlx::query("INSERT INTO entities(kind,value,first_seen,last_seen,event_count) VALUES(?,?,?,?,1) ON CONFLICT(kind,value) DO UPDATE SET last_seen=excluded.last_seen,event_count=event_count+1").bind(kind).bind(value).bind(e.timestamp.to_rfc3339()).bind(e.timestamp.to_rfc3339()).execute(db).await?;
        }
    }
    Ok(true)
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
