use crate::{event::SecurityEvent, risk::ScoreBreakdown};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
}
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum IncidentStatus {
    Active,
    Monitoring,
    AwaitingApproval,
    PendingVerification,
    Contained,
    ResponseFailed,
    Expired,
    RolledBack,
}
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ResponseState {
    Detected,
    AwaitingApproval,
    ResponseRequested,
    ResponseApplied,
    VerificationPending,
    Contained,
    ResponseFailed,
    Expired,
    RolledBack,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphEdge {
    pub from: Uuid,
    pub to: Uuid,
    pub strength: f64,
    pub reasons: Vec<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Incident {
    pub id: Uuid,
    pub created_at: DateTime<Utc>,
    pub source_ip: Option<String>,
    pub target: String,
    #[serde(default)]
    pub kind: String,
    pub risk: u8,
    pub severity: RiskLevel,
    pub status: IncidentStatus,
    /// Rule-based evidence strength (0-100), not a calibrated probability.
    /// Field name is retained for stored incident/API compatibility.
    pub confidence: u8,
    pub score: ScoreBreakdown,
    pub reasons: Vec<String>,
    pub recommended_actions: Vec<String>,
    pub events: Vec<SecurityEvent>,
    pub edges: Vec<GraphEdge>,
    pub response: Option<ResponseRecord>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseRecord {
    pub actions: Vec<String>,
    pub responded_at: DateTime<Utc>,
    pub verified_at: Option<DateTime<Utc>>,
    pub result: String,
    pub response_confidence: u8,
    pub evidence: Vec<Uuid>,
    #[serde(default)]
    pub proof: Vec<ResponseStep>,
    #[serde(default)]
    pub state: Option<ResponseState>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseStep {
    pub timestamp: DateTime<Utc>,
    pub stage: String,
    pub detail: String,
    pub http_status: Option<u16>,
}
impl RiskLevel {
    pub fn from_score(n: u8) -> Self {
        match n {
            0..=39 => Self::Low,
            40..=69 => Self::Medium,
            70..=84 => Self::High,
            _ => Self::Critical,
        }
    }
}
