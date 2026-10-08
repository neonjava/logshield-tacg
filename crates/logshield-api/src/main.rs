use axum::{
    Json, Router,
    extract::{
        DefaultBodyLimit, Multipart, Path, State, WebSocketUpgrade,
        ws::{Message, WebSocket},
    },
    http::StatusCode,
    routing::{get, post},
};
use logshield_core::{
    baseline::Baseline,
    demo::scenario,
    event::SecurityEvent,
    incident::{Incident, IncidentStatus, RiskLevel},
    normalizer::parse_line,
    response::{respond, verify},
    tacg::correlate,
};
use serde::Serialize;
use sqlx::{Row, SqlitePool};
use std::{collections::HashMap, sync::Arc};
use tokio::sync::{Mutex, broadcast, mpsc};
use tower_http::{
    cors::{Any, CorsLayer},
    trace::TraceLayer,
};

type ApiResult<T> = Result<Json<T>, (StatusCode, String)>;
#[derive(Clone)]
struct AppState {
    db: SqlitePool,
    tx: mpsc::Sender<Vec<SecurityEvent>>,
    broadcast: broadcast::Sender<String>,
    processing: Arc<Mutex<()>>,
}
#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();
    let db = SqlitePool::connect("sqlite://logshield.db?mode=rwc")
        .await
        .expect("database");
    sqlx::query("CREATE TABLE IF NOT EXISTS events(id TEXT PRIMARY KEY, timestamp TEXT NOT NULL, source_ip TEXT, payload TEXT NOT NULL)").execute(&db).await.unwrap();
    sqlx::query("CREATE TABLE IF NOT EXISTS incidents(id TEXT PRIMARY KEY, source_ip TEXT, risk INTEGER NOT NULL, payload TEXT NOT NULL)").execute(&db).await.unwrap();
    let (tx, rx) = mpsc::channel(64);
    let (broadcast, _) = broadcast::channel(256);
    let state = AppState {
        db,
        tx,
        broadcast,
        processing: Arc::new(Mutex::new(())),
    };
    tokio::spawn(worker(state.clone(), rx));
    let app = Router::new()
        .route(
            "/api/health",
            get(|| async { Json(serde_json::json!({"status":"ok","engine":"Rust TACG"})) }),
        )
        .route("/api/events", get(events).post(add_event))
        .route("/api/logs/upload", post(upload))
        .route("/api/incidents", get(incidents))
        .route("/api/incidents/{id}", get(incident))
        .route("/api/incidents/{id}/respond", post(manual_response))
        .route("/api/incidents/{id}/response", get(response))
        .route("/api/stats", get(stats))
        .route("/api/demo/{name}", post(demo))
        .route("/ws/events", get(ws))
        .layer(DefaultBodyLimit::max(1_048_576))
        .layer(
            CorsLayer::new()
                .allow_origin(Any)
                .allow_methods(Any)
                .allow_headers(Any),
        )
        .layer(TraceLayer::new_for_http())
        .with_state(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000")
        .await
        .unwrap();
    tracing::info!("listening on http://127.0.0.1:3000");
    axum::serve(listener, app).await.unwrap();
}
async fn worker(state: AppState, mut rx: mpsc::Receiver<Vec<SecurityEvent>>) {
    while let Some(batch) = rx.recv().await {
        let _guard = state.processing.lock().await;
        for e in &batch {
            let payload = serde_json::to_string(e).unwrap();
            let _ = sqlx::query(
                "INSERT OR IGNORE INTO events(id,timestamp,source_ip,payload) VALUES(?,?,?,?)",
            )
            .bind(e.id.to_string())
            .bind(e.timestamp.to_rfc3339())
            .bind(&e.source_ip)
            .bind(payload)
            .execute(&state.db)
            .await;
            let _ = state
                .broadcast
                .send(serde_json::json!({"type":"event","event":e}).to_string());
        }
        let all = load_events(&state.db).await.unwrap_or_default();
        let baseline = Baseline::learn(&all);
        for mut new in correlate(&all, &baseline) {
            let existing = sqlx::query(
                "SELECT id,payload FROM incidents WHERE source_ip=? ORDER BY risk DESC",
            )
            .bind(&new.source_ip)
            .fetch_all(&state.db)
            .await
            .unwrap_or_default();
            let ids: std::collections::HashSet<_> = new.events.iter().map(|e| e.id).collect();
            let old = existing
                .iter()
                .filter_map(|row| {
                    serde_json::from_str::<Incident>(&row.get::<String, _>("payload")).ok()
                })
                .find(|i| i.events.iter().any(|e| ids.contains(&e.id)));
            if let Some(mut old) = old {
                if old.response.is_some() {
                    let new_events: Vec<_> = new
                        .events
                        .iter()
                        .filter(|e| !old.events.iter().any(|p| p.id == e.id))
                        .cloned()
                        .collect();
                    if !new_events.is_empty() {
                        verify(&mut old, &new_events);
                        save_incident(&state.db, &old).await;
                        let _ = state.broadcast.send(
                            serde_json::json!({"type":"incident","incident":old}).to_string(),
                        );
                    }
                    continue;
                }
                new.id = old.id;
            }
            if new.severity == RiskLevel::Critical {
                respond(&mut new);
            }
            save_incident(&state.db, &new).await;
            let _ = state
                .broadcast
                .send(serde_json::json!({"type":"incident","incident":new}).to_string());
            if new.status == IncidentStatus::PendingVerification {
                let state = state.clone();
                let id = new.id.to_string();
                tokio::spawn(async move {
                    tokio::time::sleep(std::time::Duration::from_secs(3)).await;
                    let _guard = state.processing.lock().await;
                    let Ok(Json(mut current)) = incident(State(state.clone()), Path(id)).await
                    else {
                        return;
                    };
                    if current.status != IncidentStatus::PendingVerification {
                        return;
                    }
                    let events = load_events(&state.db).await.unwrap_or_default();
                    verify(&mut current, &events);
                    save_incident(&state.db, &current).await;
                    let _ = state.broadcast.send(
                        serde_json::json!({"type":"incident","incident":current}).to_string(),
                    );
                });
            }
        }
    }
}
async fn save_incident(db: &SqlitePool, i: &Incident) {
    let _=sqlx::query("INSERT INTO incidents(id,source_ip,risk,payload) VALUES(?,?,?,?) ON CONFLICT(id) DO UPDATE SET risk=excluded.risk,payload=excluded.payload").bind(i.id.to_string()).bind(&i.source_ip).bind(i.risk as i64).bind(serde_json::to_string(i).unwrap()).execute(db).await;
}
async fn load_events(db: &SqlitePool) -> Result<Vec<SecurityEvent>, sqlx::Error> {
    let rows = sqlx::query("SELECT payload FROM events ORDER BY timestamp DESC LIMIT 2000")
        .fetch_all(db)
        .await?;
    Ok(rows
        .iter()
        .filter_map(|r| serde_json::from_str(&r.get::<String, _>("payload")).ok())
        .collect())
}
async fn load_incidents(db: &SqlitePool) -> Result<Vec<Incident>, sqlx::Error> {
    let rows = sqlx::query("SELECT payload FROM incidents ORDER BY risk DESC")
        .fetch_all(db)
        .await?;
    Ok(rows
        .iter()
        .filter_map(|r| serde_json::from_str(&r.get::<String, _>("payload")).ok())
        .collect())
}
async fn events(State(s): State<AppState>) -> ApiResult<Vec<SecurityEvent>> {
    Ok(Json(load_events(&s.db).await.map_err(internal)?))
}
async fn add_event(
    State(s): State<AppState>,
    Json(e): Json<SecurityEvent>,
) -> ApiResult<serde_json::Value> {
    s.tx.send(vec![e]).await.map_err(internal)?;
    Ok(Json(serde_json::json!({"queued":1})))
}
async fn upload(
    State(s): State<AppState>,
    mut multipart: Multipart,
) -> ApiResult<serde_json::Value> {
    let mut batch = Vec::new();
    let mut rejected = 0;
    while let Some(field) = multipart.next_field().await.map_err(bad)? {
        let filename = field.file_name().unwrap_or("logs.txt");
        if ![".log", ".txt", ".jsonl"]
            .iter()
            .any(|ext| filename.ends_with(ext))
        {
            return Err((
                StatusCode::BAD_REQUEST,
                "only .log, .txt and .jsonl files accepted".into(),
            ));
        }
        let bytes = field.bytes().await.map_err(bad)?;
        if bytes.len() > 1_048_576 {
            return Err((
                StatusCode::PAYLOAD_TOO_LARGE,
                "maximum upload is 1 MiB".into(),
            ));
        }
        let text = std::str::from_utf8(&bytes).map_err(bad)?;
        for line in text.lines().take(5000) {
            match parse_line(line) {
                Ok(e) => batch.push(e),
                Err(_) => rejected += 1,
            }
        }
    }
    if batch.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "no valid security events found".into(),
        ));
    }
    let count = batch.len();
    s.tx.send(batch).await.map_err(internal)?;
    Ok(Json(
        serde_json::json!({"queued":count,"rejected":rejected}),
    ))
}
async fn incidents(State(s): State<AppState>) -> ApiResult<Vec<Incident>> {
    Ok(Json(load_incidents(&s.db).await.map_err(internal)?))
}
async fn incident(State(s): State<AppState>, Path(id): Path<String>) -> ApiResult<Incident> {
    let row = sqlx::query("SELECT payload FROM incidents WHERE id=?")
        .bind(id)
        .fetch_optional(&s.db)
        .await
        .map_err(internal)?
        .ok_or((StatusCode::NOT_FOUND, "incident not found".into()))?;
    Ok(Json(
        serde_json::from_str(&row.get::<String, _>("payload")).map_err(internal)?,
    ))
}
async fn manual_response(State(s): State<AppState>, Path(id): Path<String>) -> ApiResult<Incident> {
    let Json(mut i) = incident(State(s.clone()), Path(id)).await?;
    respond(&mut i);
    let all = load_events(&s.db).await.map_err(internal)?;
    verify(&mut i, &all);
    save_incident(&s.db, &i).await;
    let _ = s
        .broadcast
        .send(serde_json::json!({"type":"incident","incident":i}).to_string());
    Ok(Json(i))
}
async fn response(
    State(s): State<AppState>,
    Path(id): Path<String>,
) -> ApiResult<serde_json::Value> {
    let Json(i) = incident(State(s), Path(id)).await?;
    Ok(Json(
        serde_json::json!({"status":i.status,"response":i.response}),
    ))
}
#[derive(Serialize)]
struct Stats {
    events_processed: usize,
    active_incidents: usize,
    critical_incidents: usize,
    contained_incidents: usize,
    average_risk: f64,
    risk_distribution: HashMap<String, usize>,
    host_activity: HashMap<String, usize>,
}
async fn stats(State(s): State<AppState>) -> ApiResult<Stats> {
    let events = load_events(&s.db).await.map_err(internal)?;
    let incidents = load_incidents(&s.db).await.map_err(internal)?;
    let mut risk_distribution = HashMap::new();
    let mut host_activity = HashMap::new();
    for i in &incidents {
        *risk_distribution
            .entry(format!("{:?}", i.severity).to_uppercase())
            .or_insert(0) += 1;
    }
    for e in &events {
        if let Some(h) = &e.hostname {
            *host_activity.entry(h.clone()).or_insert(0) += 1;
        }
    }
    let average_risk = if incidents.is_empty() {
        0.0
    } else {
        incidents.iter().map(|i| i.risk as f64).sum::<f64>() / incidents.len() as f64
    };
    Ok(Json(Stats {
        events_processed: events.len(),
        active_incidents: incidents
            .iter()
            .filter(|i| {
                matches!(
                    i.status,
                    IncidentStatus::Active
                        | IncidentStatus::Monitoring
                        | IncidentStatus::ResponseFailed
                )
            })
            .count(),
        critical_incidents: incidents
            .iter()
            .filter(|i| i.severity == RiskLevel::Critical)
            .count(),
        contained_incidents: incidents
            .iter()
            .filter(|i| i.status == IncidentStatus::Contained)
            .count(),
        average_risk,
        risk_distribution,
        host_activity,
    }))
}
async fn demo(State(s): State<AppState>, Path(name): Path<String>) -> ApiResult<serde_json::Value> {
    if !["normal", "bruteforce", "distributed", "multistage"].contains(&name.as_str()) {
        return Err((StatusCode::NOT_FOUND, "unknown scenario".into()));
    }
    let batch = scenario(&name);
    let n = batch.len();
    s.tx.send(batch).await.map_err(internal)?;
    Ok(Json(serde_json::json!({"scenario":name,"queued":n})))
}
async fn ws(ws: WebSocketUpgrade, State(s): State<AppState>) -> impl axum::response::IntoResponse {
    ws.on_upgrade(move |socket| socket_loop(socket, s.broadcast.subscribe()))
}
async fn socket_loop(mut socket: WebSocket, mut rx: broadcast::Receiver<String>) {
    while let Ok(msg) = rx.recv().await {
        if socket.send(Message::Text(msg.into())).await.is_err() {
            break;
        }
    }
}
fn internal<E: std::fmt::Display>(e: E) -> (StatusCode, String) {
    tracing::error!("{e}");
    (StatusCode::INTERNAL_SERVER_ERROR, "internal error".into())
}
fn bad<E: std::fmt::Display>(e: E) -> (StatusCode, String) {
    (StatusCode::BAD_REQUEST, e.to_string())
}
