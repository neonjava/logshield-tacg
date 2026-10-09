use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier, password_hash::SaltString};
use axum::{
    Json, Router,
    extract::State,
    http::{HeaderMap, StatusCode},
    routing::{get, post},
};
use chrono::Utc;
use logshield_core::event::{EventType, SecurityEvent};
use rand::{Rng, rngs::OsRng};
use serde::Deserialize;
use serde_json::{Value, json};
use sqlx::{PgPool, Row};
use std::{path::PathBuf, sync::Arc};
use tokio::io::AsyncWriteExt;
use uuid::Uuid;

type Reply = Result<Json<Value>, (StatusCode, Json<Value>)>;
#[derive(Clone)]
struct App {
    name: String,
    role: String,
    log: PathBuf,
    db: PgPool,
    redis: redis::Client,
}
#[derive(Deserialize)]
struct Login {
    username: String,
    password: String,
}
#[derive(Deserialize)]
struct Mfa {
    challenge_id: String,
    code: String,
}
#[derive(Deserialize)]
struct Session {
    token: String,
}
#[derive(Deserialize)]
struct DemoCode {
    challenge_id: String,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();
    let name = std::env::var("INFRA_NAME").expect("INFRA_NAME");
    let role = std::env::var("INFRA_ROLE").expect("INFRA_ROLE");
    assert!(["infra-a", "infra-b", "infra-c"].contains(&name.as_str()));
    assert!(["operations", "reports", "inventory"].contains(&role.as_str()));
    let pg_url = std::env::var("APP_DATABASE_URL").expect("APP_DATABASE_URL");
    let db = loop {
        match PgPool::connect(&pg_url).await {
            Ok(pool) => break pool,
            Err(e) => {
                tracing::warn!(%e, "waiting for PostgreSQL");
                tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            }
        }
    };
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS users(username TEXT PRIMARY KEY, password_hash TEXT NOT NULL)",
    )
    .execute(&db)
    .await
    .expect("users schema");
    sqlx::query("CREATE TABLE IF NOT EXISTS activities(id TEXT PRIMARY KEY, username TEXT NOT NULL, service TEXT NOT NULL, replica TEXT NOT NULL, created_at TEXT NOT NULL)").execute(&db).await.expect("activities schema");
    let demo_password = std::env::var("LAB_DEMO_PASSWORD").expect("LAB_DEMO_PASSWORD");
    let salt = SaltString::generate(&mut OsRng);
    let hash = Argon2::default()
        .hash_password(demo_password.as_bytes(), &salt)
        .expect("password hash")
        .to_string();
    sqlx::query("INSERT INTO users(username,password_hash) VALUES('demo',$1) ON CONFLICT(username) DO NOTHING").bind(hash).execute(&db).await.expect("seed demo user");
    let redis =
        redis::Client::open(std::env::var("REDIS_URL").expect("REDIS_URL")).expect("redis URL");
    let log = PathBuf::from(format!(
        "{}/{}.log",
        std::env::var("LOG_DIR").unwrap_or_else(|_| "/logs".into()),
        name
    ));
    let state = Arc::new(App {
        name,
        role,
        log,
        db,
        redis,
    });
    let app = Router::new()
        .route("/health", get(health))
        .route("/password", post(password))
        .route("/mfa", post(mfa))
        .route("/session", post(session))
        .route("/activity", post(activity))
        .route("/internal/activities", get(activities))
        .route("/internal/demo-code", post(demo_code))
        .route("/internal/revoke", post(revoke_session))
        .route("/internal/session-active", post(session_active))
        .with_state(state);
    let listener = tokio::net::TcpListener::bind("0.0.0.0:8080")
        .await
        .expect("bind");
    axum::serve(listener, app).await.expect("server");
}
fn source(h: &HeaderMap) -> &str {
    h.get("x-lab-source")
        .and_then(|v| v.to_str().ok())
        .filter(|s| ["normal-client", "attacker-lab"].contains(s))
        .unwrap_or("unknown-lab-client")
}
fn event(s: &App, h: &HeaderMap, kind: EventType, action: &str, result: &str) -> SecurityEvent {
    let mut e = SecurityEvent::new(kind, Utc::now(), source(h), &s.name);
    e.destination_ip = Some(s.name.clone());
    e.username = Some("demo".into());
    e.service = Some("portal".into());
    e.action = Some(action.into());
    e.result = Some(result.into());
    e.request_id = Some(
        h.get("x-request-id")
            .and_then(|v| v.to_str().ok())
            .filter(|v| v.len() <= 64)
            .map(str::to_owned)
            .unwrap_or_else(|| Uuid::new_v4().to_string()),
    );
    e.raw_message = format!("{} {} {}", s.name, action, result);
    e
}
async fn log(s: &App, e: &SecurityEvent) -> Result<(), (StatusCode, Json<Value>)> {
    if let Some(parent) = s.log.parent() {
        tokio::fs::create_dir_all(parent).await.map_err(io_error)?;
    }
    let mut file = tokio::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&s.log)
        .await
        .map_err(io_error)?;
    file.write_all(serde_json::to_string(e).expect("event JSON").as_bytes())
        .await
        .map_err(io_error)?;
    file.write_all(b"\n").await.map_err(io_error)?;
    file.flush().await.map_err(io_error)
}
fn io_error(e: std::io::Error) -> (StatusCode, Json<Value>) {
    tracing::error!(%e, "log write failed");
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(json!({"error":"log write failed"})),
    )
}
fn store_error(e: redis::RedisError) -> (StatusCode, Json<Value>) {
    tracing::error!(%e, "Redis unavailable");
    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(json!({"error":"session store unavailable"})),
    )
}
async fn health(State(s): State<Arc<App>>) -> Result<Json<Value>, StatusCode> {
    sqlx::query("SELECT 1")
        .fetch_one(&s.db)
        .await
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    let mut conn = s
        .redis
        .get_multiplexed_async_connection()
        .await
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    let pong: String = redis::cmd("PING")
        .query_async(&mut conn)
        .await
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    Ok(Json(
        json!({"status":"ok","replica":s.name,"role":s.role,"postgres":true,"redis":pong == "PONG"}),
    ))
}
async fn password(State(s): State<Arc<App>>, h: HeaderMap, Json(body): Json<Login>) -> Reply {
    if body.username.len() > 128 || body.password.len() > 128 {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({"error":"invalid input"})),
        ));
    }
    let row = sqlx::query("SELECT password_hash FROM users WHERE username=$1")
        .bind(&body.username)
        .fetch_optional(&s.db)
        .await
        .map_err(|_| {
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({"error":"user store unavailable"})),
            )
        })?;
    let valid = row
        .and_then(|r| r.try_get::<String, _>("password_hash").ok())
        .is_some_and(|hash| {
            PasswordHash::new(&hash).is_ok_and(|parsed| {
                Argon2::default()
                    .verify_password(body.password.as_bytes(), &parsed)
                    .is_ok()
            })
        });
    if !valid {
        let mut e = event(&s, &h, EventType::FailedLogin, "password_login", "failure");
        e.username = Some(body.username);
        log(&s, &e).await?;
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(json!({"authenticated":false,"served_by":s.name,"request_id":e.request_id})),
        ));
    }
    let challenge = Uuid::new_v4().to_string();
    let code = format!("{:06}", rand::thread_rng().gen_range(0..1_000_000));
    let mut conn = s
        .redis
        .get_multiplexed_async_connection()
        .await
        .map_err(store_error)?;
    let value = format!("{}|{}|{}", body.username, source(&h), code);
    redis::cmd("SETEX")
        .arg(format!("lab:challenge:{challenge}"))
        .arg(300)
        .arg(value)
        .query_async::<()>(&mut conn)
        .await
        .map_err(store_error)?;
    let mut e = event(
        &s,
        &h,
        EventType::PasswordAccepted,
        "password_login",
        "challenge_required",
    );
    e.challenge_id = Some(challenge.clone());
    log(&s, &e).await?;
    Ok(Json(
        json!({"challenge_id":challenge,"mfa_required":true,"served_by":s.name,"request_id":e.request_id}),
    ))
}
async fn mfa(State(s): State<Arc<App>>, h: HeaderMap, Json(body): Json<Mfa>) -> Reply {
    if Uuid::parse_str(&body.challenge_id).is_err()
        || body.code.len() != 6
        || !body.code.bytes().all(|b| b.is_ascii_digit())
    {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({"error":"invalid challenge or code"})),
        ));
    }
    let mut conn = s
        .redis
        .get_multiplexed_async_connection()
        .await
        .map_err(store_error)?;
    let key = format!("lab:challenge:{}", body.challenge_id);
    let stored: Option<String> = redis::cmd("GET")
        .arg(&key)
        .query_async(&mut conn)
        .await
        .map_err(store_error)?;
    let Some(stored) = stored else {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(json!({"error":"challenge expired"})),
        ));
    };
    let parts: Vec<_> = stored.split('|').collect();
    if parts.len() != 3 || parts[1] != source(&h) {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(json!({"error":"challenge source mismatch"})),
        ));
    }
    if parts[2] != body.code {
        let mut e = event(&s, &h, EventType::MfaFailure, "mfa_verify", "failure");
        e.username = Some(parts[0].into());
        e.challenge_id = Some(body.challenge_id);
        log(&s, &e).await?;
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(json!({"mfa_verified":false,"served_by":s.name,"request_id":e.request_id})),
        ));
    }
    redis::cmd("DEL")
        .arg(&key)
        .query_async::<()>(&mut conn)
        .await
        .map_err(store_error)?;
    let token = Uuid::new_v4().to_string();
    redis::cmd("SETEX")
        .arg(format!("lab:session:{token}"))
        .arg(600)
        .arg(format!("{}|{}", parts[0], source(&h)))
        .query_async::<()>(&mut conn)
        .await
        .map_err(store_error)?;
    redis::cmd("SETEX")
        .arg(format!("lab:completed:{}", body.challenge_id))
        .arg(600)
        .arg(&token)
        .query_async::<()>(&mut conn)
        .await
        .map_err(store_error)?;
    let mut e = event(&s, &h, EventType::MfaSuccess, "mfa_verify", "success");
    e.challenge_id = Some(body.challenge_id.clone());
    log(&s, &e).await?;
    let mut completed = event(
        &s,
        &h,
        EventType::SuccessfulLogin,
        "completed_login",
        "success",
    );
    completed.challenge_id = Some(body.challenge_id);
    log(&s, &completed).await?;
    Ok(Json(
        json!({"authenticated":true,"token":token,"expires_in_seconds":600,"served_by":s.name,"request_id":completed.request_id}),
    ))
}
async fn authorize(
    s: &App,
    h: &HeaderMap,
    token: &str,
) -> Result<String, (StatusCode, Json<Value>)> {
    if Uuid::parse_str(token).is_err() {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(json!({"error":"invalid session"})),
        ));
    }
    let mut conn = s
        .redis
        .get_multiplexed_async_connection()
        .await
        .map_err(store_error)?;
    let value: Option<String> = redis::cmd("GET")
        .arg(format!("lab:session:{token}"))
        .query_async(&mut conn)
        .await
        .map_err(store_error)?;
    let Some(value) = value else {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(json!({"error":"session expired"})),
        ));
    };
    let Some((user, bound_source)) = value.split_once('|') else {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(json!({"error":"invalid session"})),
        ));
    };
    if bound_source != source(h) {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(json!({"error":"session source mismatch"})),
        ));
    }
    Ok(user.into())
}
async fn session(State(s): State<Arc<App>>, h: HeaderMap, Json(body): Json<Session>) -> Reply {
    let user = authorize(&s, &h, &body.token).await?;
    let mut e = event(&s, &h, EventType::WebRequest, "session_check", "success");
    e.username = Some(user.clone());
    log(&s, &e).await?;
    Ok(Json(
        json!({"session_valid":true,"username":user,"served_by":s.name,"request_id":e.request_id}),
    ))
}
async fn activity(State(s): State<Arc<App>>, h: HeaderMap, Json(body): Json<Session>) -> Reply {
    let user = authorize(&s, &h, &body.token).await?;
    let id = Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO activities(id,username,service,replica,created_at) VALUES($1,$2,$3,$4,$5)",
    )
    .bind(&id)
    .bind(&user)
    .bind(&s.role)
    .bind(&s.name)
    .bind(Utc::now().to_rfc3339())
    .execute(&s.db)
    .await
    .map_err(|_| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"error":"activity store unavailable"})),
        )
    })?;
    let mut e = event(&s, &h, EventType::ServiceActivity, &s.role, "success");
    e.username = Some(user);
    log(&s, &e).await?;
    Ok(Json(
        json!({"activity_id":id,"service":s.role,"served_by":s.name,"request_id":e.request_id}),
    ))
}
async fn demo_code(State(s): State<Arc<App>>, Json(body): Json<DemoCode>) -> Reply {
    if Uuid::parse_str(&body.challenge_id).is_err() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({"error":"invalid challenge"})),
        ));
    }
    let mut conn = s
        .redis
        .get_multiplexed_async_connection()
        .await
        .map_err(store_error)?;
    let value: Option<String> = redis::cmd("GET")
        .arg(format!("lab:challenge:{}", body.challenge_id))
        .query_async(&mut conn)
        .await
        .map_err(store_error)?;
    let code = value
        .and_then(|v| v.split('|').nth(2).map(str::to_owned))
        .ok_or((
            StatusCode::NOT_FOUND,
            Json(json!({"error":"challenge expired"})),
        ))?;
    Ok(Json(json!({"demo_code":code})))
}
async fn activities(State(s): State<Arc<App>>) -> Reply {
    let rows = sqlx::query("SELECT id,username,service,replica,created_at FROM activities ORDER BY created_at DESC LIMIT 30")
        .fetch_all(&s.db).await.map_err(|_| (StatusCode::SERVICE_UNAVAILABLE, Json(json!({"error":"activity store unavailable"}))))?;
    Ok(Json(
        json!({"activities":rows.iter().map(|r| json!({"id":r.get::<String,_>("id"),"username":r.get::<String,_>("username"),"service":r.get::<String,_>("service"),"replica":r.get::<String,_>("replica"),"created_at":r.get::<String,_>("created_at")})).collect::<Vec<_>>()}),
    ))
}
async fn revoke_session(State(s): State<Arc<App>>, Json(body): Json<DemoCode>) -> Reply {
    if Uuid::parse_str(&body.challenge_id).is_err() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({"error":"invalid challenge"})),
        ));
    }
    let mut conn = s
        .redis
        .get_multiplexed_async_connection()
        .await
        .map_err(store_error)?;
    let mapping = format!("lab:completed:{}", body.challenge_id);
    let token: Option<String> = redis::cmd("GET")
        .arg(&mapping)
        .query_async(&mut conn)
        .await
        .map_err(store_error)?;
    let Some(token) = token else {
        return Ok(Json(json!({"revoked":false})));
    };
    redis::cmd("DEL")
        .arg(format!("lab:session:{token}"))
        .query_async::<()>(&mut conn)
        .await
        .map_err(store_error)?;
    redis::cmd("DEL")
        .arg(&mapping)
        .query_async::<()>(&mut conn)
        .await
        .map_err(store_error)?;
    Ok(Json(json!({"revoked":true,"token":token})))
}
async fn session_active(State(s): State<Arc<App>>, Json(body): Json<Session>) -> Reply {
    if Uuid::parse_str(&body.token).is_err() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({"error":"invalid token"})),
        ));
    }
    let mut conn = s
        .redis
        .get_multiplexed_async_connection()
        .await
        .map_err(store_error)?;
    let value: Option<String> = redis::cmd("GET")
        .arg(format!("lab:session:{}", body.token))
        .query_async(&mut conn)
        .await
        .map_err(store_error)?;
    Ok(Json(json!({"active":value.is_some()})))
}
