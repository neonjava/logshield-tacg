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
    PendingVerification,
    Contained,
    ResponseFailed,
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
    pub risk: u8,
    pub severity: RiskLevel,
    pub status: IncidentStatus,
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
