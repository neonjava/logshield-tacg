use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventType {
    Connection,
    MultiPortActivity,
    FailedLogin,
    SuccessfulLogin,
    PrivilegeAction,
    UnusualNetworkActivity,
    WebRequest,
    ServiceActivity,
    UnauthorizedAccess,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityEvent {
    #[serde(default = "Uuid::new_v4")]
    pub id: Uuid,
    #[serde(default = "Utc::now")]
    pub timestamp: DateTime<Utc>,
    pub event_type: EventType,
    pub source_ip: Option<String>,
    pub destination_ip: Option<String>,
    pub hostname: Option<String>,
    pub username: Option<String>,
    pub service: Option<String>,
    pub port: Option<u16>,
    pub action: Option<String>,
    pub result: Option<String>,
    pub severity_hint: Option<String>,
    #[serde(default)]
    pub raw_message: String,
}
impl SecurityEvent {
    pub fn new(event_type: EventType, timestamp: DateTime<Utc>, source: &str, host: &str) -> Self {
        Self {
            id: Uuid::new_v4(),
            timestamp,
            event_type,
            source_ip: Some(source.into()),
            destination_ip: None,
            hostname: Some(host.into()),
            username: None,
            service: None,
            port: None,
            action: None,
            result: None,
            severity_hint: None,
            raw_message: String::new(),
        }
    }
}
