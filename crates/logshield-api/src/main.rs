mod database;
mod sensor;
use axum::{
    Json, Router,
    extract::{
        DefaultBodyLimit, Multipart, Path, State, WebSocketUpgrade,
        ws::{Message, WebSocket},
    },
    http::{HeaderMap, Request, StatusCode, header},
    middleware::{self, Next},
    response::IntoResponse,
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
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
};
use tokio::sync::{Mutex, broadcast, mpsc, oneshot};
use tower_http::{
    cors::{Any, CorsLayer},
    trace::TraceLayer,
};

type ApiResult<T> = Result<Json<T>, (StatusCode, String)>;
struct WorkItem {
    events: Vec<SecurityEvent>,
    persisted: Option<oneshot::Sender<Result<(), String>>>,
}
impl WorkItem {
    fn background(events: Vec<SecurityEvent>) -> Self {
        Self {
            events,
            persisted: None,
        }
    }
}
#[derive(Clone)]
struct AppState {
    db: SqlitePool,
    tx: mpsc::Sender<WorkItem>,
    broadcast: broadcast::Sender<String>,
    processing: Arc<Mutex<()>>,
    response_gate: Arc<Mutex<()>>,
    reset_generation: Arc<AtomicU64>,
    reset_at: Arc<Mutex<Option<chrono::DateTime<Utc>>>>,
    client: reqwest::Client,
    gateway: String,
    attacker: String,
    lab_mode: bool,
    log_dir: PathBuf,
    sensor_online: Arc<AtomicBool>,
    offsets: sensor::Offsets,
    ingest_tokens: HashMap<String, String>,
    operator_token: Option<String>,
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
    let lab_mode = std::env::var("LAB_MODE").is_ok_and(|value| value == "true");
    let operator_token = std::env::var("LOGSHIELD_OPERATOR_TOKEN").ok();
    if !lab_mode && operator_token.as_ref().is_none_or(|token| token.len() < 24) {
        panic!("LOGSHIELD_OPERATOR_TOKEN must be at least 24 characters in non-lab mode");
    }
    let state = AppState {
        db: pool,
        tx,
        broadcast,
        processing: Arc::new(Mutex::new(())),
        response_gate: Arc::new(Mutex::new(())),
        reset_generation: Arc::new(AtomicU64::new(0)),
        reset_at: Arc::new(Mutex::new(None)),
        client: reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .build()
            .unwrap(),
        gateway: std::env::var("GATEWAY_URL").unwrap_or_else(|_| "http://127.0.0.1:8081".into()),
        attacker: std::env::var("ATTACKER_URL").unwrap_or_else(|_| "http://127.0.0.1:8082".into()),
        lab_mode,
        log_dir: log_dir.clone(),
        sensor_online: Arc::new(AtomicBool::new(false)),
        offsets: Arc::new(Mutex::new(HashMap::new())),
        ingest_tokens: load_ingest_tokens(),
        operator_token,
    };
    tokio::spawn(worker(state.clone(), rx));
    tokio::spawn(sensor::start(
        log_dir,
        state.tx.clone(),
        state.sensor_online.clone(),
        state.offsets.clone(),
    ));
    let protected = Router::new()
        .route("/api/status", get(status))
        .route("/api/events", get(events).post(add_event))
        .route("/api/logs/upload", post(upload))
        .route("/api/logs/sample/{name}", get(sample_logs))
        .route("/api/logs/export", get(export_logs))
        .route("/api/infra/status", get(infra_status))
        .route("/api/infra/activities", get(infra_activities))
        .route("/api/infra/request", post(infra_request))
        .route("/api/infra/run/{name}", post(infra_run))
        .route("/api/entities", get(entities))
        .route("/api/incidents", get(incidents))
        .route("/api/incidents/{id}", get(incident))
        .route("/api/incidents/{id}/respond", post(manual_response))
        .route("/api/incidents/{id}/response", get(response_status))
        .route("/api/responses", get(responses))
        .route("/api/stats", get(stats))
        .route("/api/lab/run/{name}", post(run_lab))
        .route("/api/lab/attempt", post(lab_attempt))
        .route("/api/lab/force-failure", post(force_failure))
        .route("/api/lab/clear", post(clear_lab))
        .route("/ws/events", get(ws))
        .route_layer(middleware::from_fn_with_state(state.clone(), operator_auth));
    let mut app = Router::new()
        .route("/api/health", get(health))
        .route("/api/ingest/events", post(ingest_events))
        .route("/api/ingest/heartbeat", post(ingest_heartbeat))
        .merge(protected)
        .layer(DefaultBodyLimit::max(1_048_576))
        .layer(TraceLayer::new_for_http());
    if state.lab_mode {
        app = app.layer(
            CorsLayer::new()
                .allow_origin(Any)
                .allow_methods(Any)
                .allow_headers(Any),
        );
    }
    let app = app.with_state(state);
    let bind = std::env::var("API_BIND").unwrap_or_else(|_| "127.0.0.1:3000".into());
    let listener = tokio::net::TcpListener::bind(&bind)
        .await
        .expect("API_BIND");
    tracing::info!(%bind,"LogShield API ready");
    axum::serve(listener, app).await.unwrap();
}
async fn operator_auth(
    State(state): State<AppState>,
    request: Request<axum::body::Body>,
    next: Next,
) -> impl IntoResponse {
    if !state.lab_mode {
        let expected = state.operator_token.as_deref().unwrap_or_default();
        let authorized = request
            .headers()
            .get(header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.strip_prefix("Bearer "))
            .is_some_and(|provided| constant_time_eq(provided.as_bytes(), expected.as_bytes()));
        if !authorized {
            return Err((StatusCode::UNAUTHORIZED, "operator authentication required"));
        }
    }
    Ok(next.run(request).await)
}
fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut difference = 0_u8;
    for (a, b) in left.iter().zip(right) {
        difference |= a ^ b;
    }
    difference == 0
}
fn load_ingest_tokens() -> HashMap<String, String> {
    let mut tokens: HashMap<String, String> = [
        ("infra-a", "LOGSHIELD_INGEST_A"),
        ("infra-b", "LOGSHIELD_INGEST_B"),
        ("infra-c", "LOGSHIELD_INGEST_C"),
    ]
    .into_iter()
    .filter_map(|(source, key)| std::env::var(key).ok().map(|token| (source.into(), token)))
    .collect();
    if let Ok(value) = std::env::var("LOGSHIELD_INGEST_TOKENS")
        && !value.trim().is_empty()
    {
        let extra: HashMap<String, String> =
            serde_json::from_str(&value).expect("LOGSHIELD_INGEST_TOKENS must be a JSON object");
        for (source, token) in extra {
            assert!(
                !source.is_empty()
                    && source.len() <= 64
                    && source
                        .bytes()
                        .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_'),
                "invalid ingestion source name"
            );
            tokens.insert(source, token);
        }
    }
    assert!(
        tokens.values().all(|token| token.len() >= 24),
        "ingestion tokens must contain at least 24 characters"
    );
    let unique: std::collections::HashSet<_> = tokens.values().collect();
    assert_eq!(
        unique.len(),
        tokens.len(),
        "ingestion tokens must be unique"
    );
    tokens
}
async fn worker(state: AppState, mut rx: mpsc::Receiver<WorkItem>) {
    while let Some(work) = rx.recv().await {
        let _guard = state.processing.lock().await;
        let result = process_batch(&state, &work.events).await;
        if let Err(err) = &result {
            tracing::error!(%err, "batch processing failed");
        }
        if let Some(ack) = work.persisted {
            let _ = ack.send(result);
        }
    }
}
async fn process_batch(state: &AppState, batch: &[SecurityEvent]) -> Result<(), String> {
    let reset_at = *state.reset_at.lock().await;
    for e in batch {
        if reset_at.is_some_and(|cutoff| {
            e.timestamp <= cutoff
                && e.origin
                    .as_deref()
                    .is_some_and(|origin| origin == "lab_sensor" || origin.starts_with("agent:"))
        }) {
            continue;
        }
        match db::insert_event(&state.db, e).await {
            Ok(true) => {
                let _ = state
                    .broadcast
                    .send(serde_json::json!({"type":"event","event":e}).to_string());
            }
            Ok(false) => {}
            Err(err) => return Err(format!("event insert failed: {err}")),
        }
    }
    if batch.is_empty() {
        return Ok(());
    }
    let all = db::events(&state.db).await.map_err(|e| e.to_string())?;
    let baseline = Baseline::learn(&all);
    let existing = db::incidents(&state.db).await.map_err(|e| e.to_string())?;
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
        if response::eligible(&new)
            && state.lab_mode
            && new.events.iter().all(|e| {
                e.origin
                    .as_deref()
                    .is_some_and(|origin| origin == "lab_sensor" || origin.starts_with("agent:"))
            })
        {
            response::begin(&mut new);
        }
        if let Err(err) = db::save_incident(&state.db, &new).await {
            return Err(format!("incident save failed: {err}"));
        }
        let _ = state
            .broadcast
            .send(serde_json::json!({"type":"incident","incident":new}).to_string());
        if new.status == IncidentStatus::PendingVerification {
            let state = state.clone();
            let id = new.id.to_string();
            let generation = state.reset_generation.load(Ordering::SeqCst);
            tokio::spawn(async move {
                execute_response(state, id, generation).await;
            });
        }
    }
    Ok(())
}
async fn execute_response(state: AppState, id: String, generation: u64) {
    let _guard = state.response_gate.lock().await;
    if state.reset_generation.load(Ordering::SeqCst) != generation {
        return;
    }
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
    let mut session_verified = true;
    if incident.kind == "SUSPICIOUS SUCCESSFUL LOGIN" || incident.kind == "UNUSUAL SUCCESSFUL LOGIN"
    {
        session_verified = false;
        let challenge = incident
            .events
            .iter()
            .rev()
            .find(|e| e.event_type == logshield_core::event::EventType::SuccessfulLogin)
            .and_then(|e| e.challenge_id.clone());
        if let Some(challenge_id) = challenge {
            let revoked = state
                .client
                .post(format!("{}/internal/infra/revoke", state.gateway))
                .json(&serde_json::json!({"challenge_id":challenge_id}))
                .send()
                .await
                .ok();
            if let Some(r) = revoked.and_then(|r| r.error_for_status().ok())
                && let Ok(body) = r.json::<Value>().await
                && body["revoked"] == true
                && let Some(token) = body["token"].as_str()
            {
                response::record(
                    &mut incident,
                    "SESSION_REVOKED",
                    "shared Redis session deleted".into(),
                    Some(200),
                );
                if let Ok(r) = state
                    .client
                    .post(format!("{}/internal/infra/session-active", state.gateway))
                    .json(&serde_json::json!({"token":token}))
                    .send()
                    .await
                    && let Ok(check) = r.json::<Value>().await
                {
                    session_verified = check["active"] == false;
                }
            }
        }
        response::record(
            &mut incident,
            if session_verified {
                "SESSION_REVOCATION_VERIFIED"
            } else {
                "SESSION_REVOCATION_FAILED"
            },
            if session_verified {
                "revoked session is no longer active".into()
            } else {
                "could not verify session revocation; human intervention required".into()
            },
            None,
        );
    }
    response::record(
        &mut incident,
        "VERIFICATION_REQUEST_SENT",
        "attacker-lab retries a fixed login through the gateway".into(),
        None,
    );
    let verify_result = if incident.target.starts_with("infra-") {
        state
            .client
            .post(format!("{}/infra/password", state.gateway))
            .header("x-lab-source", "attacker-lab")
            .json(&serde_json::json!({"username":"demo","password":"incorrect"}))
            .send()
            .await
    } else {
        state
            .client
            .post(format!("{}/verify", state.attacker))
            .send()
            .await
    };
    let observation = match verify_result {
        Ok(r) => {
            if incident.target.starts_with("infra-") {
                let status = r.status().as_u16();
                let body = r.json::<Value>().await.unwrap_or_default();
                serde_json::json!({"status":status,"body":body})
            } else {
                r.json::<Value>()
                    .await
                    .unwrap_or_else(|e| serde_json::json!({"error":e.to_string(),"status":0}))
            }
        }
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
    response::finish(
        &mut incident,
        blocked && applied && session_verified,
        http_status,
        matched,
    );
    if !session_verified && let Some(record) = incident.response.as_mut() {
        record.result = "Gateway result recorded, but shared session revocation was not verified; human intervention required".into();
    }
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
async fn infra_status(State(s): State<AppState>) -> ApiResult<Value> {
    let r = s
        .client
        .get(format!("{}/internal/infra-status", s.gateway))
        .send()
        .await
        .map_err(internal)?;
    let mut body = r.json::<Value>().await.map_err(internal)?;
    let rows = sqlx::query("SELECT source,seen_at FROM source_heartbeats")
        .fetch_all(&s.db)
        .await
        .map_err(internal)?;
    let agents: Vec<Value> = ["infra-a", "infra-b", "infra-c"]
        .iter()
        .map(|name| {
            let online = rows
                .iter()
                .find(|r| r.get::<String, _>("source") == *name)
                .and_then(|r| {
                    chrono::DateTime::parse_from_rfc3339(&r.get::<String, _>("seen_at")).ok()
                })
                .is_some_and(|t| {
                    Utc::now()
                        .signed_duration_since(t.with_timezone(&Utc))
                        .num_seconds()
                        < 15
                });
            serde_json::json!({"name":name,"online":online})
        })
        .collect();
    body["agents"] = serde_json::json!(agents);
    Ok(Json(body))
}
async fn infra_activities(State(s): State<AppState>) -> ApiResult<Value> {
    let r = s
        .client
        .get(format!("{}/internal/infra-activities", s.gateway))
        .send()
        .await
        .map_err(internal)?;
    Ok(Json(r.json::<Value>().await.map_err(internal)?))
}
fn ingest_source(s: &AppState, headers: &HeaderMap) -> Result<String, (StatusCode, String)> {
    let credential = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .unwrap_or("");
    s.ingest_tokens
        .iter()
        .find(|(_, token)| !credential.is_empty() && token.as_str() == credential)
        .map(|(name, _)| name.clone())
        .ok_or((StatusCode::UNAUTHORIZED, "invalid ingestion token".into()))
}
async fn ingest_heartbeat(State(s): State<AppState>, headers: HeaderMap) -> ApiResult<Value> {
    let source = ingest_source(&s, &headers)?;
    sqlx::query("INSERT INTO source_heartbeats(source,seen_at) VALUES(?,?) ON CONFLICT(source) DO UPDATE SET seen_at=excluded.seen_at")
        .bind(&source).bind(Utc::now().to_rfc3339()).execute(&s.db).await.map_err(internal)?;
    Ok(Json(serde_json::json!({"source":source,"ok":true})))
}
#[derive(Deserialize, Serialize, Clone)]
struct InfraRequest {
    action: String,
    source: String,
    password: Option<String>,
    challenge_id: Option<String>,
    code: Option<String>,
    token: Option<String>,
}
async fn send_infra(s: &AppState, body: &InfraRequest) -> ApiResult<Value> {
    if !s.lab_mode {
        return Err((StatusCode::SERVICE_UNAVAILABLE, "lab disabled".into()));
    }
    if ![
        "password",
        "password-a",
        "mfa",
        "session",
        "operations",
        "reports",
        "inventory",
        "demo-code",
    ]
    .contains(&body.action.as_str())
        || !["normal-client", "attacker-lab"].contains(&body.source.as_str())
        || [&body.password, &body.challenge_id, &body.code, &body.token]
            .iter()
            .any(|v| v.as_ref().is_some_and(|s| s.len() > 128))
    {
        return Err((
            StatusCode::BAD_REQUEST,
            "fixed local infra operations only".into(),
        ));
    }
    let payload = match body.action.as_str() {
        "password" | "password-a" => {
            serde_json::json!({"username":"demo","password":body.password.as_deref().unwrap_or("")})
        }
        "mfa" => serde_json::json!({"challenge_id":body.challenge_id,"code":body.code}),
        "demo-code" => serde_json::json!({"challenge_id":body.challenge_id}),
        _ => serde_json::json!({"token":body.token}),
    };
    let r = s
        .client
        .post(format!("{}/infra/{}", s.gateway, body.action))
        .header("x-lab-source", &body.source)
        .header("x-request-id", uuid::Uuid::new_v4().to_string())
        .json(&payload)
        .send()
        .await
        .map_err(internal)?;
    let status = r.status().as_u16();
    let response = r.json::<Value>().await.unwrap_or_default();
    Ok(Json(
        serde_json::json!({"status":status,"body":response,"action":body.action}),
    ))
}
async fn infra_request(
    State(s): State<AppState>,
    Json(body): Json<InfraRequest>,
) -> ApiResult<Value> {
    send_infra(&s, &body).await
}
async fn infra_run(State(s): State<AppState>, Path(name): Path<String>) -> ApiResult<Value> {
    if !["normal", "bruteforce", "distributed", "suspicious", "mfa"].contains(&name.as_str()) {
        return Err((StatusCode::NOT_FOUND, "fixed scenarios only".into()));
    }
    let make = |action: &str,
                source: &str,
                password: Option<&str>,
                challenge_id: Option<String>,
                code: Option<String>,
                token: Option<String>| InfraRequest {
        action: action.into(),
        source: source.into(),
        password: password.map(str::to_owned),
        challenge_id,
        code,
        token,
    };
    let mut requests = Vec::new();
    if name == "normal" || name == "suspicious" || name == "mfa" {
        if name == "suspicious" {
            for _ in 0..2 {
                requests.push(
                    send_infra(
                        &s,
                        &make("password", "attacker-lab", Some("wrong"), None, None, None),
                    )
                    .await?
                    .0,
                );
                tokio::time::sleep(std::time::Duration::from_millis(350)).await;
            }
        }
        let source = if name == "normal" {
            "normal-client"
        } else {
            "attacker-lab"
        };
        let accepted = send_infra(
            &s,
            &make("password", source, Some("hackathon123"), None, None, None),
        )
        .await?
        .0;
        let challenge = accepted
            .pointer("/body/challenge_id")
            .and_then(Value::as_str)
            .ok_or((StatusCode::BAD_GATEWAY, "password step failed".into()))?
            .to_owned();
        requests.push(accepted);
        if name == "mfa" {
            let valid_code = send_infra(
                &s,
                &make(
                    "demo-code",
                    source,
                    None,
                    Some(challenge.clone()),
                    None,
                    None,
                ),
            )
            .await?
            .0;
            let wrong_code = if valid_code
                .pointer("/body/demo_code")
                .and_then(Value::as_str)
                == Some("000000")
            {
                "000001"
            } else {
                "000000"
            };
            for _ in 0..3 {
                requests.push(
                    send_infra(
                        &s,
                        &make(
                            "mfa",
                            source,
                            None,
                            Some(challenge.clone()),
                            Some(wrong_code.into()),
                            None,
                        ),
                    )
                    .await?
                    .0,
                );
                tokio::time::sleep(std::time::Duration::from_millis(350)).await;
            }
        } else {
            let code = send_infra(
                &s,
                &make(
                    "demo-code",
                    source,
                    None,
                    Some(challenge.clone()),
                    None,
                    None,
                ),
            )
            .await?
            .0;
            let valid = code
                .pointer("/body/demo_code")
                .and_then(Value::as_str)
                .ok_or((StatusCode::BAD_GATEWAY, "demo code unavailable".into()))?
                .to_owned();
            let completed = send_infra(
                &s,
                &make("mfa", source, None, Some(challenge), Some(valid), None),
            )
            .await?
            .0;
            let token = completed
                .pointer("/body/token")
                .and_then(Value::as_str)
                .ok_or((StatusCode::BAD_GATEWAY, "MFA step failed".into()))?
                .to_owned();
            requests.push(completed);
            if name == "normal" {
                for action in [
                    "session",
                    "session",
                    "session",
                    "operations",
                    "reports",
                    "inventory",
                ] {
                    requests.push(
                        send_infra(
                            &s,
                            &make(action, source, None, None, None, Some(token.clone())),
                        )
                        .await?
                        .0,
                    );
                }
            }
        }
    } else {
        let action = if name == "bruteforce" {
            "password-a"
        } else {
            "password"
        };
        let count = if name == "bruteforce" { 6 } else { 5 };
        for _ in 0..count {
            requests.push(
                send_infra(
                    &s,
                    &make(action, "attacker-lab", Some("wrong"), None, None, None),
                )
                .await?
                .0,
            );
            tokio::time::sleep(std::time::Duration::from_millis(350)).await;
        }
    }
    Ok(Json(
        serde_json::json!({"scenario":name,"requests":requests}),
    ))
}
async fn events(State(s): State<AppState>) -> ApiResult<Vec<SecurityEvent>> {
    Ok(Json(db::events(&s.db).await.map_err(internal)?))
}
async fn add_event(State(s): State<AppState>, Json(e): Json<SecurityEvent>) -> ApiResult<Value> {
    let mut e = e;
    e.origin = Some("direct_api".into());
    s.tx.send(WorkItem::background(vec![e]))
        .await
        .map_err(internal)?;
    Ok(Json(serde_json::json!({"queued":1})))
}
#[derive(Deserialize)]
struct IngestBatch {
    events: Vec<SecurityEvent>,
}
async fn ingest_events(
    State(s): State<AppState>,
    headers: HeaderMap,
    Json(mut batch): Json<IngestBatch>,
) -> ApiResult<Value> {
    let source = ingest_source(&s, &headers)?;
    if batch.events.is_empty() || batch.events.len() > 100 {
        return Err((StatusCode::BAD_REQUEST, "1-100 events required".into()));
    }
    for e in &mut batch.events {
        e.hostname = Some(source.clone());
        e.origin = Some(format!("agent:{source}"));
    }
    let count = batch.events.len();
    let (ack, wait) = oneshot::channel();
    s.tx.send(WorkItem {
        events: batch.events,
        persisted: Some(ack),
    })
    .await
    .map_err(internal)?;
    wait.await.map_err(internal)?.map_err(internal)?;
    Ok(Json(
        serde_json::json!({"queued":count,"source":source,"durable":true}),
    ))
}
async fn upload(State(s): State<AppState>, mut multipart: Multipart) -> ApiResult<Value> {
    let mut batch = Vec::new();
    let mut rejected = 0;
    let mut duplicates = 0;
    let mut seen = std::collections::HashSet::new();
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
                Ok(mut e) => {
                    if !seen.insert(e.id)
                        || sqlx::query("SELECT 1 FROM events WHERE id=?")
                            .bind(e.id.to_string())
                            .fetch_optional(&s.db)
                            .await
                            .map_err(internal)?
                            .is_some()
                    {
                        duplicates += 1;
                    } else {
                        e.origin = Some("manual_upload".into());
                        batch.push(e);
                    }
                }
                Err(_) => rejected += 1,
            }
        }
    }
    if batch.is_empty() && duplicates == 0 {
        return Err((
            StatusCode::BAD_REQUEST,
            "no valid security events found".into(),
        ));
    }
    let count = batch.len();
    if !batch.is_empty() {
        s.tx.send(WorkItem::background(batch))
            .await
            .map_err(internal)?;
    }
    Ok(Json(
        serde_json::json!({"accepted":count,"rejected":rejected,"duplicates":duplicates,"origin":"manual_upload","automatic_response":false}),
    ))
}
fn jsonl_download(filename: &str, events: &[SecurityEvent]) -> axum::response::Response {
    let mut content = String::new();
    for e in events {
        if let Ok(line) = serde_json::to_string(e) {
            content.push_str(&line);
            content.push('\n');
        }
    }
    (
        [
            (header::CONTENT_TYPE, "application/x-ndjson".to_string()),
            (
                header::CONTENT_DISPOSITION,
                format!("attachment; filename=\"{filename}\""),
            ),
        ],
        content,
    )
        .into_response()
}
async fn export_logs(
    State(s): State<AppState>,
) -> Result<axum::response::Response, (StatusCode, String)> {
    let events = db::events(&s.db).await.map_err(internal)?;
    Ok(jsonl_download("logshield-events.jsonl", &events))
}
async fn sample_logs(Path(name): Path<String>) -> Result<impl IntoResponse, (StatusCode, String)> {
    let mut events = match name.as_str() {
        "normal" | "bruteforce" | "distributed" | "multistage" => {
            logshield_core::demo::scenario(&name)
        }
        "mfa" => {
            let mut v = Vec::new();
            for i in 0..3 {
                let mut e = SecurityEvent::new(
                    logshield_core::event::EventType::MfaFailure,
                    Utc::now() + chrono::Duration::seconds(i * 8),
                    "example-source",
                    "example-auth",
                );
                e.username = Some("demo".into());
                e.service = Some("mfa".into());
                e.result = Some("failure".into());
                e.challenge_id = Some("sample-challenge".into());
                v.push(e);
            }
            v
        }
        "suspicious" => {
            let mut v = logshield_core::demo::scenario("normal");
            v.clear();
            for (i, kind) in [
                logshield_core::event::EventType::FailedLogin,
                logshield_core::event::EventType::FailedLogin,
                logshield_core::event::EventType::PasswordAccepted,
                logshield_core::event::EventType::MfaSuccess,
                logshield_core::event::EventType::SuccessfulLogin,
            ]
            .into_iter()
            .enumerate()
            {
                let mut e = SecurityEvent::new(
                    kind,
                    Utc::now() + chrono::Duration::seconds(i as i64 * 7),
                    "example-source",
                    "example-auth",
                );
                e.username = Some("demo".into());
                e.service = Some("auth".into());
                e.result = Some(if i < 2 { "failure" } else { "success" }.into());
                v.push(e);
            }
            v
        }
        _ => return Err((StatusCode::NOT_FOUND, "unknown sample".into())),
    };
    for e in &mut events {
        e.origin = Some("sample_file".into());
    }
    Ok(jsonl_download(&format!("logshield-{name}.jsonl"), &events))
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
    if i.events
        .iter()
        .any(|e| e.origin.as_deref() == Some("manual_upload"))
    {
        return Err((
            StatusCode::BAD_REQUEST,
            "manual uploads cannot control the lab gateway".into(),
        ));
    }
    if i.response.is_some() {
        return Err((StatusCode::CONFLICT, "response already attempted".into()));
    }
    response::begin(&mut i);
    db::save_incident(&s.db, &i).await.map_err(internal)?;
    let state = s.clone();
    let generation = state.reset_generation.load(Ordering::SeqCst);
    tokio::spawn(async move {
        execute_response(state, id, generation).await;
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
#[derive(Deserialize, Serialize)]
struct LabAttempt {
    app: String,
    operation: String,
    source: String,
    password: Option<String>,
}
async fn lab_attempt(State(s): State<AppState>, Json(body): Json<LabAttempt>) -> ApiResult<Value> {
    if !s.lab_mode {
        return Err((StatusCode::SERVICE_UNAVAILABLE, "lab disabled".into()));
    }
    if !["app-a", "app-b", "app-c"].contains(&body.app.as_str())
        || !["login", "lab/admin-operation", "lab/outbound"].contains(&body.operation.as_str())
        || !["attacker-lab", "normal-client"].contains(&body.source.as_str())
        || body.password.as_ref().is_some_and(|p| p.len() > 128)
    {
        return Err((
            StatusCode::BAD_REQUEST,
            "fixed local lab targets and operations only".into(),
        ));
    }
    let r = s
        .client
        .post(format!("{}/attempt", s.attacker))
        .json(&body)
        .send()
        .await
        .map_err(internal)?;
    let status = r.status();
    let payload = r.json::<Value>().await.map_err(internal)?;
    if !status.is_success() {
        return Err((StatusCode::BAD_GATEWAY, payload.to_string()));
    }
    Ok(Json(payload))
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
    let _response_guard = s.response_gate.lock().await;
    s.reset_generation.fetch_add(1, Ordering::SeqCst);
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
    *s.reset_at.lock().await = Some(Utc::now());
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

#[cfg(test)]
mod auth_tests {
    use super::constant_time_eq;

    #[test]
    fn operator_token_requires_exact_match() {
        assert!(constant_time_eq(
            b"a-long-private-token",
            b"a-long-private-token"
        ));
        assert!(!constant_time_eq(
            b"a-long-private-token",
            b"a-long-private-tokeN"
        ));
        assert!(!constant_time_eq(b"short", b"a-long-private-token"));
    }
}
