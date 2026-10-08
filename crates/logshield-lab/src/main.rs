use axum::{
    Json, Router,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    routing::{get, post},
};
use chrono::{DateTime, Duration, Utc};
use logshield_core::event::{EventType, SecurityEvent};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, path::PathBuf, sync::Arc};
use tokio::{io::AsyncWriteExt, sync::Mutex};
use uuid::Uuid;

type Reply = Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)>;
#[derive(Clone)]
struct AppState {
    name: String,
    log: PathBuf,
}
#[derive(Clone)]
struct GatewayState {
    client: Client,
    blocks: Arc<Mutex<HashMap<String, Block>>>,
    force_failure: Arc<Mutex<bool>>,
    log: PathBuf,
    block_file: PathBuf,
}
#[derive(Clone)]
struct AttackerState {
    client: Client,
    gateway: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Block {
    source: String,
    incident_id: String,
    reason: String,
    expires_at: DateTime<Utc>,
}
#[derive(Deserialize)]
struct BlockRequest {
    source: String,
    incident_id: String,
    reason: String,
    duration_seconds: i64,
}
#[derive(Deserialize)]
struct Login {
    username: String,
    password: String,
}
#[derive(Deserialize)]
struct FailureToggle {
    enabled: bool,
}
#[derive(Serialize, Deserialize)]
struct Attempt {
    status: u16,
    body: serde_json::Value,
    request_id: String,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();
    let role = std::env::var("LAB_ROLE").unwrap_or_else(|_| "app".into());
    let bind = std::env::var("LAB_BIND").unwrap_or_else(|_| "0.0.0.0:8080".into());
    let client = Client::builder()
        .timeout(std::time::Duration::from_secs(3))
        .build()
        .unwrap();
    let app = match role.as_str() {
        "app" => {
            let name = std::env::var("APP_NAME").expect("APP_NAME");
            assert!(["app-a", "app-b", "app-c"].contains(&name.as_str()));
            let log = PathBuf::from(format!(
                "{}/{}.log",
                std::env::var("LOG_DIR").unwrap_or_else(|_| "./lab-logs".into()),
                name
            ));
            let state = AppState { name, log };
            Router::new()
                .route(
                    "/health",
                    get(|| async { Json(serde_json::json!({"status":"ok"})) }),
                )
                .route("/login", post(login))
                .route("/lab/admin-operation", post(admin_operation))
                .route("/lab/outbound", post(outbound))
                .with_state(state)
        }
        "gateway" => {
            let log_dir = std::env::var("LOG_DIR").unwrap_or_else(|_| "./lab-logs".into());
            let block_file = PathBuf::from(
                std::env::var("BLOCK_FILE").unwrap_or_else(|_| "./lab-state/blocks.json".into()),
            );
            let blocks = tokio::fs::read(&block_file)
                .await
                .ok()
                .and_then(|bytes| serde_json::from_slice::<HashMap<String, Block>>(&bytes).ok())
                .unwrap_or_default();
            let state = GatewayState {
                client,
                blocks: Arc::new(Mutex::new(blocks)),
                force_failure: Arc::new(Mutex::new(false)),
                log: PathBuf::from(format!("{log_dir}/gateway.log")),
                block_file,
            };
            Router::new()
                .route(
                    "/health",
                    get(|| async { Json(serde_json::json!({"status":"ok"})) }),
                )
                .route("/internal/services", get(services))
                .route("/internal/block", post(block))
                .route("/internal/force-failure", post(force_failure))
                .route("/internal/reset", post(reset_gateway))
                .route("/{app}/{*path}", post(proxy))
                .with_state(state)
        }
        "attacker" => {
            let state = AttackerState {
                client,
                gateway: std::env::var("GATEWAY_URL")
                    .unwrap_or_else(|_| "http://gateway:8080".into()),
            };
            Router::new()
                .route(
                    "/health",
                    get(|| async { Json(serde_json::json!({"status":"ok"})) }),
                )
                .route("/run/{name}", post(run))
                .route("/verify", post(verify))
                .with_state(state)
        }
        _ => panic!("unknown LAB_ROLE"),
    };
    let listener = tokio::net::TcpListener::bind(&bind).await.unwrap();
    tracing::info!(role,%bind,"lab service ready");
    axum::serve(listener, app).await.unwrap();
}
async fn append_log(path: &PathBuf, e: &SecurityEvent) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    let mut f = tokio::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .await?;
    f.write_all(serde_json::to_string(e).unwrap().as_bytes())
        .await?;
    f.write_all(b"\n").await?;
    f.flush().await
}
fn source(headers: &HeaderMap) -> String {
    headers
        .get("x-lab-source")
        .and_then(|v| v.to_str().ok())
        .filter(|x| ["attacker-lab", "normal-client"].contains(x))
        .unwrap_or("unknown-lab-client")
        .to_owned()
}
fn request_id(headers: &HeaderMap) -> String {
    headers
        .get("x-request-id")
        .and_then(|v| v.to_str().ok())
        .filter(|x| x.len() <= 64)
        .map(str::to_owned)
        .unwrap_or_else(|| Uuid::new_v4().to_string())
}
fn app_event(
    state: &AppState,
    headers: &HeaderMap,
    kind: EventType,
    user: Option<String>,
    result: &str,
    action: &str,
) -> SecurityEvent {
    let mut e = SecurityEvent::new(kind, Utc::now(), &source(headers), &state.name);
    e.destination_ip = Some(state.name.clone());
    e.username = user;
    e.service = Some("auth".into());
    e.result = Some(result.into());
    e.action = Some(action.into());
    e.request_id = Some(request_id(headers));
    e.raw_message = format!("{} {} {}", state.name, action, result);
    e
}
async fn login(State(s): State<AppState>, headers: HeaderMap, Json(body): Json<Login>) -> Reply {
    if body.username.len() > 128 || body.password.len() > 128 {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error":"invalid input"})),
        ));
    }
    let good = body.username == "demo" && body.password == "hackathon123";
    let mut e = app_event(
        &s,
        &headers,
        if good {
            EventType::SuccessfulLogin
        } else {
            EventType::FailedLogin
        },
        Some(body.username),
        if good { "success" } else { "failure" },
        "login",
    );
    e.raw_message = format!(
        "{} login {} request_id={}",
        s.name,
        e.result.as_deref().unwrap_or(""),
        e.request_id.as_deref().unwrap_or("")
    );
    append_log(&s.log, &e).await.map_err(server_error)?;
    if good {
        Ok(Json(
            serde_json::json!({"authenticated":true,"request_id":e.request_id}),
        ))
    } else {
        Err((
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"authenticated":false,"request_id":e.request_id})),
        ))
    }
}
async fn admin_operation(State(s): State<AppState>, headers: HeaderMap) -> Reply {
    let e = app_event(
        &s,
        &headers,
        EventType::PrivilegeAction,
        Some("demo".into()),
        "success",
        "lab_admin_operation",
    );
    append_log(&s.log, &e).await.map_err(server_error)?;
    Ok(Json(
        serde_json::json!({"lab_operation":"completed","request_id":e.request_id}),
    ))
}
async fn outbound(State(s): State<AppState>, headers: HeaderMap) -> Reply {
    let mut e = app_event(
        &s,
        &headers,
        EventType::UnusualNetworkActivity,
        Some("demo".into()),
        "success",
        "local_outbound_style_request",
    );
    e.service = Some("network".into());
    append_log(&s.log, &e).await.map_err(server_error)?;
    Ok(Json(
        serde_json::json!({"lab_outbound":"local_only","request_id":e.request_id}),
    ))
}
fn server_error(e: std::io::Error) -> (StatusCode, Json<serde_json::Value>) {
    tracing::error!(%e,"log write failed");
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(serde_json::json!({"error":"log write failed"})),
    )
}
fn target(app: &str) -> Option<String> {
    match app {
        "app-a" => Some(std::env::var("APP_A_URL").unwrap_or_else(|_| "http://app-a:8080".into())),
        "app-b" => Some(std::env::var("APP_B_URL").unwrap_or_else(|_| "http://app-b:8080".into())),
        "app-c" => Some(std::env::var("APP_C_URL").unwrap_or_else(|_| "http://app-c:8080".into())),
        _ => None,
    }
}
async fn proxy(
    State(s): State<GatewayState>,
    Path((app, path)): Path<(String, String)>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, Json<serde_json::Value>)> {
    let base = target(&app).ok_or((
        StatusCode::NOT_FOUND,
        Json(serde_json::json!({"error":"unknown lab service"})),
    ))?;
    if !["login", "lab/admin-operation", "lab/outbound"].contains(&path.as_str()) {
        return Err((
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error":"fixed lab paths only"})),
        ));
    }
    let src = source(&headers);
    let blocked = {
        let mut blocks = s.blocks.lock().await;
        blocks.retain(|_, b| b.expires_at > Utc::now());
        blocks.get(&src).cloned()
    };
    if let Some(b) = blocked {
        let mut e = SecurityEvent::new(EventType::UnauthorizedAccess, Utc::now(), &src, "gateway");
        e.destination_ip = Some(app.clone());
        e.result = Some("blocked".into());
        e.action = Some("gateway_denylist".into());
        e.service = Some("gateway".into());
        e.request_id = Some(request_id(&headers));
        e.raw_message = format!(
            "gateway blocked source={} incident={} target={}",
            src, b.incident_id, app
        );
        append_log(&s.log, &e).await.map_err(server_error)?;
        return Err((
            StatusCode::FORBIDDEN,
            Json(
                serde_json::json!({"blocked":true,"incident_id":b.incident_id,"reason":"automated containment","request_id":e.request_id}),
            ),
        ));
    }
    let url = format!("{base}/{path}");
    let mut req = s
        .client
        .post(url)
        .header("x-lab-source", src)
        .header("x-request-id", request_id(&headers))
        .body(body);
    if let Some(ct) = headers.get(axum::http::header::CONTENT_TYPE) {
        req = req.header(reqwest::header::CONTENT_TYPE, ct.as_bytes());
    }
    let resp = req.send().await.map_err(|e| {
        tracing::error!(%e,"app unavailable");
        (
            StatusCode::BAD_GATEWAY,
            Json(serde_json::json!({"error":"lab service unavailable"})),
        )
    })?;
    let status = StatusCode::from_u16(resp.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
    let payload = resp
        .json::<serde_json::Value>()
        .await
        .unwrap_or_else(|_| serde_json::json!({"error":"invalid app response"}));
    Ok((status, Json(payload)))
}
async fn persist_blocks(s: &GatewayState, blocks: &HashMap<String, Block>) -> std::io::Result<()> {
    if let Some(parent) = s.block_file.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    let tmp = s.block_file.with_extension("tmp");
    tokio::fs::write(&tmp, serde_json::to_vec(blocks).unwrap()).await?;
    tokio::fs::rename(tmp, &s.block_file).await
}
async fn block(State(s): State<GatewayState>, Json(body): Json<BlockRequest>) -> Reply {
    if *s.force_failure.lock().await {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({"applied":false,"reason":"forced lab response failure"})),
        ));
    }
    if body.source != "attacker-lab"
        || body.duration_seconds < 1
        || body.duration_seconds > 300
        || body.incident_id.len() > 64
    {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error":"invalid lab block request"})),
        ));
    }
    let record = Block {
        source: body.source.clone(),
        incident_id: body.incident_id,
        reason: body.reason,
        expires_at: Utc::now() + Duration::seconds(body.duration_seconds),
    };
    let mut blocks = s.blocks.lock().await;
    blocks.insert(body.source.clone(), record.clone());
    persist_blocks(&s, &blocks).await.map_err(server_error)?;
    Ok(Json(serde_json::json!({"applied":true,"block":record})))
}
async fn force_failure(
    State(s): State<GatewayState>,
    Json(body): Json<FailureToggle>,
) -> Json<serde_json::Value> {
    *s.force_failure.lock().await = body.enabled;
    Json(serde_json::json!({"force_response_failure":body.enabled}))
}
async fn reset_gateway(State(s): State<GatewayState>) -> Reply {
    let mut blocks = s.blocks.lock().await;
    blocks.clear();
    persist_blocks(&s, &blocks).await.map_err(server_error)?;
    *s.force_failure.lock().await = false;
    Ok(Json(serde_json::json!({"reset":true})))
}
async fn services(State(s): State<GatewayState>) -> Json<serde_json::Value> {
    let mut online = 0;
    for app in ["app-a", "app-b", "app-c"] {
        if let Some(base) = target(app)
            && s.client
                .get(format!("{base}/health"))
                .send()
                .await
                .is_ok_and(|r| r.status().is_success())
        {
            online += 1;
        }
    }
    let forced = *s.force_failure.lock().await;
    Json(serde_json::json!({"online":online,"total":3,"force_response_failure":forced}))
}
async fn attempt(
    s: &AttackerState,
    app: &str,
    path: &str,
    password: Option<&str>,
    source: &str,
) -> Attempt {
    let id = Uuid::new_v4().to_string();
    let url = format!("{}/{app}/{path}", s.gateway);
    let mut req = s
        .client
        .post(url)
        .header("x-lab-source", source)
        .header("x-request-id", &id);
    if let Some(password) = password {
        req = req.json(&serde_json::json!({"username":"demo","password":password}));
    }
    match req.send().await {
        Ok(r) => {
            let status = r.status().as_u16();
            let body = r
                .json::<serde_json::Value>()
                .await
                .unwrap_or(serde_json::json!({}));
            Attempt {
                status,
                body,
                request_id: id,
            }
        }
        Err(e) => Attempt {
            status: 0,
            body: serde_json::json!({"error":e.to_string()}),
            request_id: id,
        },
    }
}
async fn run(State(s): State<AttackerState>, Path(name): Path<String>) -> Reply {
    let steps: Vec<(&str, &str, Option<&str>, &str)> = match name.as_str() {
        "normal" => vec![
            ("app-a", "login", Some("hackathon123"), "normal-client"),
            ("app-b", "login", Some("hackathon123"), "normal-client"),
            ("app-c", "login", Some("hackathon123"), "normal-client"),
        ],
        "distributed" => vec![
            ("app-a", "login", Some("incorrect"), "attacker-lab"),
            ("app-a", "login", Some("incorrect"), "attacker-lab"),
            ("app-b", "login", Some("incorrect"), "attacker-lab"),
            ("app-b", "login", Some("incorrect"), "attacker-lab"),
            ("app-c", "login", Some("incorrect"), "attacker-lab"),
        ],
        "multistage" => vec![
            ("app-a", "login", Some("incorrect"), "attacker-lab"),
            ("app-a", "login", Some("incorrect"), "attacker-lab"),
            ("app-a", "login", Some("hackathon123"), "attacker-lab"),
            ("app-a", "lab/admin-operation", None, "attacker-lab"),
            ("app-a", "lab/outbound", None, "attacker-lab"),
        ],
        _ => {
            return Err((
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({"error":"fixed scenarios only"})),
            ));
        }
    };
    let mut attempts = Vec::new();
    for (app, path, password, source) in steps {
        attempts.push(attempt(&s, app, path, password, source).await);
        tokio::time::sleep(std::time::Duration::from_millis(350)).await;
    }
    Ok(Json(
        serde_json::json!({"scenario":name,"requests":attempts}),
    ))
}
async fn verify(State(s): State<AttackerState>) -> Json<Attempt> {
    Json(attempt(&s, "app-a", "login", Some("incorrect"), "attacker-lab").await)
}
