mod database;
mod sensor;
use axum::{
    Json, Router,
    extract::{
        DefaultBodyLimit, Multipart, Path, State, WebSocketUpgrade,
        ws::{Message, WebSocket},
    },
    http::StatusCode,
    routing::{get, post},
};
use chrono::Utc;
use database as db;
use logshield_core::{
    baseline::Baseline,
    event::SecurityEvent,
    incident::{Incident, IncidentStatus},
    normalizer::parse_line,
    response,
    tacg::correlate,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::{Row, SqlitePool};
use std::{
    collections::HashMap,
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};
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
    client: reqwest::Client,
    gateway: String,
    attacker: String,
    lab_mode: bool,
    log_dir: PathBuf,
    sensor_online: Arc<AtomicBool>,
    offsets: sensor::Offsets,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();
    let database_url =
        std::env::var("DATABASE_URL").unwrap_or_else(|_| "sqlite://logshield.db?mode=rwc".into());
    let pool = SqlitePool::connect(&database_url).await.expect("database");
    db::init(&pool).await.expect("database schema");
    let (tx, rx) = mpsc::channel(256);
    let (broadcast, _) = broadcast::channel(512);
    let log_dir = PathBuf::from(std::env::var("LOG_DIR").unwrap_or_else(|_| "./lab-logs".into()));
    let state = AppState {
        db: pool,
        tx,
        broadcast,
        processing: Arc::new(Mutex::new(())),
        client: reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .build()
            .unwrap(),
        gateway: std::env::var("GATEWAY_URL").unwrap_or_else(|_| "http://127.0.0.1:8081".into()),
        attacker: std::env::var("ATTACKER_URL").unwrap_or_else(|_| "http://127.0.0.1:8082".into()),
        lab_mode: std::env::var("LAB_MODE").unwrap_or_else(|_| "true".into()) == "true",
        log_dir: log_dir.clone(),
        sensor_online: Arc::new(AtomicBool::new(false)),
        offsets: Arc::new(Mutex::new(HashMap::new())),
    };
    tokio::spawn(worker(state.clone(), rx));
    tokio::spawn(sensor::start(
        log_dir,
        state.tx.clone(),
        state.sensor_online.clone(),
        state.offsets.clone(),
    ));
    let app = Router::new()
        .route("/api/health", get(health))
        .route("/api/status", get(status))
        .route("/api/events", get(events).post(add_event))
        .route("/api/logs/upload", post(upload))
        .route("/api/entities", get(entities))
        .route("/api/incidents", get(incidents))
        .route("/api/incidents/{id}", get(incident))
        .route("/api/incidents/{id}/respond", post(manual_response))
        .route("/api/incidents/{id}/response", get(response_status))
        .route("/api/responses", get(responses))
        .route("/api/stats", get(stats))
        .route("/api/lab/run/{name}", post(run_lab))
        .route("/api/lab/force-failure", post(force_failure))
        .route("/api/lab/clear", post(clear_lab))
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
    let bind = std::env::var("API_BIND").unwrap_or_else(|_| "127.0.0.1:3000".into());
    let listener = tokio::net::TcpListener::bind(&bind)
        .await
        .expect("API_BIND");
    tracing::info!(%bind,"LogShield API ready");
    axum::serve(listener, app).await.unwrap();
}
async fn worker(state: AppState, mut rx: mpsc::Receiver<Vec<SecurityEvent>>) {
    while let Some(batch) = rx.recv().await {
        let _guard = state.processing.lock().await;
        let mut inserted = false;
        for e in &batch {
            match db::insert_event(&state.db, e).await {
                Ok(true) => {
                    inserted = true;
                    let _ = state
                        .broadcast
                        .send(serde_json::json!({"type":"event","event":e}).to_string());
                }
                Ok(false) => {}
                Err(err) => tracing::error!(%err,"event insert failed"),
            }
        }
        if !inserted {
            continue;
        }
        let all = db::events(&state.db).await.unwrap_or_default();
        let baseline = Baseline::learn(&all);
        let existing = db::incidents(&state.db).await.unwrap_or_default();
        for mut new in correlate(&all, &baseline) {
            let ids: std::collections::HashSet<_> = new.events.iter().map(|e| e.id).collect();
            if let Some(old) = existing
                .iter()
                .find(|i| i.events.iter().any(|e| ids.contains(&e.id)))
            {
                if old.response.is_some() {
                    continue;
                }
                new.id = old.id;
            }
            if response::eligible(&new) && state.lab_mode {
                response::begin(&mut new);
            }
            if let Err(err) = db::save_incident(&state.db, &new).await {
                tracing::error!(%err,"incident save failed");
                continue;
            }
            let _ = state
                .broadcast
                .send(serde_json::json!({"type":"incident","incident":new}).to_string());
            if new.status == IncidentStatus::PendingVerification {
                let state = state.clone();
                let id = new.id.to_string();
                tokio::spawn(async move {
                    execute_response(state, id).await;
                });
            }
        }
    }
}
async fn execute_response(state: AppState, id: String) {
    let Some(mut incident) = db::incident(&state.db, &id).await.ok().flatten() else {
        return;
    };
    let source = incident.source_ip.clone().unwrap_or_default();
    let payload = serde_json::json!({"source":source,"incident_id":id,"reason":"high confidence correlated intrusion","duration_seconds":60});
    let block_result = state
        .client
        .post(format!("{}/internal/block", state.gateway))
        .json(&payload)
        .send()
        .await;
    let (applied, block_status, block_body) = match block_result {
        Ok(r) => {
            let status = r.status().as_u16();
            let body = r.json::<Value>().await.unwrap_or_default();
            (
                status == 200 && body.get("applied") == Some(&Value::Bool(true)),
                status,
                body,
            )
        }
        Err(e) => (false, 0, serde_json::json!({"error":e.to_string()})),
    };
    response::record(
        &mut incident,
        if applied {
            "GATEWAY_BLOCK_APPLIED"
        } else {
            "GATEWAY_BLOCK_FAILED"
        },
        block_body.to_string(),
        Some(block_status),
    );
    if applied {
        let _=sqlx::query("INSERT OR REPLACE INTO gateway_blocks(incident_id,source,expires_at,payload) VALUES(?,?,?,?)").bind(&id).bind(&source).bind(block_body.pointer("/block/expires_at").and_then(Value::as_str).unwrap_or("")).bind(block_body.to_string()).execute(&state.db).await;
    }
    response::record(
        &mut incident,
        "VERIFICATION_REQUEST_SENT",
        "attacker-lab retries a fixed login through the gateway".into(),
        None,
    );
    let verify_result = state
        .client
        .post(format!("{}/verify", state.attacker))
        .send()
        .await;
    let observation = match verify_result {
        Ok(r) => r
            .json::<Value>()
            .await
            .unwrap_or_else(|e| serde_json::json!({"error":e.to_string(),"status":0})),
        Err(e) => serde_json::json!({"error":e.to_string(),"status":0}),
    };
    let http_status = observation
        .get("status")
        .and_then(Value::as_u64)
        .unwrap_or(0) as u16;
    let blocked = observation.pointer("/body/blocked") == Some(&Value::Bool(true));
    let matched = observation
        .pointer("/body/incident_id")
        .and_then(Value::as_str)
        == Some(id.as_str());
    response::record(
        &mut incident,
        if http_status == 403 {
            "HTTP_403_RECEIVED"
        } else {
            "VERIFICATION_HTTP_RESULT"
        },
        observation.to_string(),
        Some(http_status),
    );
    response::finish(&mut incident, blocked && applied, http_status, matched);
    let _=sqlx::query("INSERT INTO verification_attempts(id,incident_id,timestamp,http_status,blocked,matched,payload) VALUES(?,?,?,?,?,?,?)").bind(uuid::Uuid::new_v4().to_string()).bind(&id).bind(Utc::now().to_rfc3339()).bind(http_status as i64).bind(blocked).bind(matched).bind(observation.to_string()).execute(&state.db).await;
    if let Err(e) = db::save_incident(&state.db, &incident).await {
        tracing::error!(%e,"response save failed");
    }
    let _ = state
        .broadcast
        .send(serde_json::json!({"type":"incident","incident":incident}).to_string());
}
async fn health() -> Json<Value> {
    Json(serde_json::json!({"status":"ok","engine":"Rust TACG"}))
}
async fn status(State(s): State<AppState>) -> ApiResult<Value> {
    let gateway = s
        .client
        .get(format!("{}/health", s.gateway))
        .send()
        .await
        .is_ok_and(|r| r.status().is_success());
    let attacker = s
        .client
        .get(format!("{}/health", s.attacker))
        .send()
        .await
        .is_ok_and(|r| r.status().is_success());
    let services = s
        .client
        .get(format!("{}/internal/services", s.gateway))
        .send()
        .await
        .ok();
    let service_body = if let Some(r) = services {
        r.json::<Value>().await.unwrap_or_default()
    } else {
        Value::Null
    };
    let database = sqlx::query("SELECT 1").fetch_one(&s.db).await.is_ok();
    let recent = sqlx::query("SELECT COUNT(*) AS n FROM events WHERE timestamp>=?")
        .bind((Utc::now() - chrono::Duration::seconds(60)).to_rfc3339())
        .fetch_one(&s.db)
        .await
        .map(|r| r.get::<i64, _>("n"))
        .unwrap_or(0);
    let last = sqlx::query("SELECT timestamp FROM events ORDER BY timestamp DESC LIMIT 1")
        .fetch_optional(&s.db)
        .await
        .ok()
        .flatten()
        .map(|r| r.get::<String, _>("timestamp"));
    Ok(Json(
        serde_json::json!({"gateway":gateway,"attacker":attacker,"sensor":s.sensor_online.load(Ordering::Relaxed),"tacg":true,"database":database,"services_online":service_body.get("online").and_then(Value::as_u64).unwrap_or(0),"services_total":3,"force_response_failure":service_body.get("force_response_failure").and_then(Value::as_bool).unwrap_or(false),"events_per_second":recent as f64/60.0,"last_event":last}),
    ))
}
async fn events(State(s): State<AppState>) -> ApiResult<Vec<SecurityEvent>> {
    Ok(Json(db::events(&s.db).await.map_err(internal)?))
}
async fn add_event(State(s): State<AppState>, Json(e): Json<SecurityEvent>) -> ApiResult<Value> {
    s.tx.send(vec![e]).await.map_err(internal)?;
    Ok(Json(serde_json::json!({"queued":1})))
}
async fn upload(State(s): State<AppState>, mut multipart: Multipart) -> ApiResult<Value> {
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
async fn entities(State(s): State<AppState>) -> ApiResult<Vec<Value>> {
    let rows=sqlx::query("SELECT kind,value,first_seen,last_seen,event_count FROM entities ORDER BY event_count DESC LIMIT 100").fetch_all(&s.db).await.map_err(internal)?;
    Ok(Json(rows.iter().map(|r|serde_json::json!({"kind":r.get::<String,_>("kind"),"value":r.get::<String,_>("value"),"first_seen":r.get::<String,_>("first_seen"),"last_seen":r.get::<String,_>("last_seen"),"event_count":r.get::<i64,_>("event_count")})).collect()))
}
async fn incidents(State(s): State<AppState>) -> ApiResult<Vec<Incident>> {
    Ok(Json(db::incidents(&s.db).await.map_err(internal)?))
}
async fn incident(State(s): State<AppState>, Path(id): Path<String>) -> ApiResult<Incident> {
    db::incident(&s.db, &id)
        .await
        .map_err(internal)?
        .map(Json)
        .ok_or((StatusCode::NOT_FOUND, "incident not found".into()))
}
async fn manual_response(State(s): State<AppState>, Path(id): Path<String>) -> ApiResult<Incident> {
    let mut i = db::incident(&s.db, &id)
        .await
        .map_err(internal)?
        .ok_or((StatusCode::NOT_FOUND, "incident not found".into()))?;
    if !s.lab_mode {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "lab gateway not configured".into(),
        ));
    }
    if i.response.is_some() {
        return Err((StatusCode::CONFLICT, "response already attempted".into()));
    }
    response::begin(&mut i);
    db::save_incident(&s.db, &i).await.map_err(internal)?;
    let state = s.clone();
    tokio::spawn(async move {
        execute_response(state, id).await;
    });
    Ok(Json(i))
}
async fn response_status(State(s): State<AppState>, Path(id): Path<String>) -> ApiResult<Value> {
    let i = db::incident(&s.db, &id)
        .await
        .map_err(internal)?
        .ok_or((StatusCode::NOT_FOUND, "incident not found".into()))?;
    let rows = sqlx::query(
        "SELECT payload FROM verification_attempts WHERE incident_id=? ORDER BY timestamp",
    )
    .bind(&id)
    .fetch_all(&s.db)
    .await
    .map_err(internal)?;
    let attempts: Vec<Value> = rows
        .iter()
        .filter_map(|r| serde_json::from_str(&r.get::<String, _>("payload")).ok())
        .collect();
    Ok(Json(
        serde_json::json!({"status":i.status,"response":i.response,"verification_attempts":attempts}),
    ))
}
async fn responses(State(s): State<AppState>) -> ApiResult<Vec<Value>> {
    let rows = sqlx::query("SELECT incident_id,status,payload FROM responses ORDER BY rowid DESC")
        .fetch_all(&s.db)
        .await
        .map_err(internal)?;
    Ok(Json(rows.iter().map(|r|serde_json::json!({"incident_id":r.get::<String,_>("incident_id"),"status":r.get::<String,_>("status"),"response":serde_json::from_str::<Value>(&r.get::<String,_>("payload")).unwrap_or_default()})).collect()))
}
#[derive(Serialize)]
struct Stats {
    events_processed: usize,
    active_incidents: usize,
    critical_incidents: usize,
    contained_incidents: usize,
    response_failures: usize,
    risk_distribution: HashMap<String, usize>,
    host_activity: HashMap<String, usize>,
}
async fn stats(State(s): State<AppState>) -> ApiResult<Stats> {
    let events = db::events(&s.db).await.map_err(internal)?;
    let incidents = db::incidents(&s.db).await.map_err(internal)?;
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
    Ok(Json(Stats {
        events_processed: events.len(),
        active_incidents: incidents
            .iter()
            .filter(|i| {
                matches!(
                    i.status,
                    IncidentStatus::Active
                        | IncidentStatus::Monitoring
                        | IncidentStatus::PendingVerification
                        | IncidentStatus::ResponseFailed
                )
            })
            .count(),
        critical_incidents: incidents.iter().filter(|i| i.risk >= 85).count(),
        contained_incidents: incidents
            .iter()
            .filter(|i| i.status == IncidentStatus::Contained)
            .count(),
        response_failures: incidents
            .iter()
            .filter(|i| i.status == IncidentStatus::ResponseFailed)
            .count(),
        risk_distribution,
        host_activity,
    }))
}
async fn run_lab(State(s): State<AppState>, Path(name): Path<String>) -> ApiResult<Value> {
    if !s.lab_mode {
        return Err((StatusCode::SERVICE_UNAVAILABLE, "lab disabled".into()));
    }
    if !["normal", "distributed", "multistage"].contains(&name.as_str()) {
        return Err((StatusCode::NOT_FOUND, "fixed scenarios only".into()));
    }
    let r = s
        .client
        .post(format!("{}/run/{name}", s.attacker))
        .send()
        .await
        .map_err(internal)?;
    let status = r.status();
    let body = r.json::<Value>().await.map_err(internal)?;
    if !status.is_success() {
        return Err((StatusCode::BAD_GATEWAY, body.to_string()));
    }
    Ok(Json(body))
}
#[derive(Deserialize)]
struct Toggle {
    enabled: bool,
}
async fn force_failure(State(s): State<AppState>, Json(toggle): Json<Toggle>) -> ApiResult<Value> {
    if !s.lab_mode {
        return Err((StatusCode::SERVICE_UNAVAILABLE, "lab disabled".into()));
    }
    let r = s
        .client
        .post(format!("{}/internal/force-failure", s.gateway))
        .json(&serde_json::json!({"enabled":toggle.enabled}))
        .send()
        .await
        .map_err(internal)?;
    Ok(Json(r.json::<Value>().await.map_err(internal)?))
}
async fn clear_lab(State(s): State<AppState>) -> ApiResult<Value> {
    if !s.lab_mode {
        return Err((StatusCode::SERVICE_UNAVAILABLE, "lab disabled".into()));
    }
    let _guard = s.processing.lock().await;
    let r = s
        .client
        .post(format!("{}/internal/reset", s.gateway))
        .send()
        .await
        .map_err(internal)?;
    if !r.status().is_success() {
        return Err((StatusCode::BAD_GATEWAY, "gateway reset failed".into()));
    }
    sensor::skip_existing(&s.log_dir, &s.offsets).await;
    db::clear(&s.db).await.map_err(internal)?;
    let _ = s
        .broadcast
        .send(serde_json::json!({"type":"reset"}).to_string());
    Ok(Json(
        serde_json::json!({"cleared":true,"note":"database and denylist cleared; raw lab logs retained"}),
    ))
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
    tracing::error!(%e,"internal error");
    (StatusCode::INTERNAL_SERVER_ERROR, "internal error".into())
}
fn bad<E: std::fmt::Display>(e: E) -> (StatusCode, String) {
    (StatusCode::BAD_REQUEST, e.to_string())
}
