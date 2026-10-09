use crate::incident::{Incident, IncidentStatus, ResponseRecord, ResponseState, ResponseStep};
use chrono::Utc;

pub const RESPONSE_RISK_THRESHOLD: u8 = 85;
pub const RESPONSE_CONFIDENCE_THRESHOLD: u8 = 85;

pub fn eligible(incident: &Incident) -> bool {
    incident.risk >= RESPONSE_RISK_THRESHOLD
        && incident.confidence >= RESPONSE_CONFIDENCE_THRESHOLD
        && incident.response.is_none()
}

pub fn request_approval(incident: &mut Incident) {
    incident.status = IncidentStatus::AwaitingApproval;
    incident.response = Some(ResponseRecord {
        actions: vec!["Awaiting operator review and response approval".into()],
        responded_at: Utc::now(),
        verified_at: None,
        result: "Detection flagged as eligible for containment; awaiting operator approval".into(),
        response_confidence: incident.confidence,
        evidence: incident.events.iter().map(|e| e.id).collect(),
        proof: vec![ResponseStep {
            timestamp: Utc::now(),
            stage: "AWAITING_APPROVAL".into(),
            detail: format!(
                "High-confidence threat (Risk: {}, Confidence: {}); operator approval required outside lab mode",
                incident.risk, incident.confidence
            ),
            http_status: None,
        }],
        state: Some(ResponseState::AwaitingApproval),
    });
}

pub fn begin(incident: &mut Incident) {
    incident.response = Some(ResponseRecord {
        actions: vec!["Request 60-second source block at the lab gateway".into()],
        responded_at: Utc::now(),
        verified_at: None,
        result: "Gateway action requested; waiting for real HTTP verification".into(),
        response_confidence: incident.confidence,
        evidence: incident.events.iter().map(|e| e.id).collect(),
        proof: vec![ResponseStep {
            timestamp: Utc::now(),
            stage: "ACTION_REQUESTED".into(),
            detail: format!(
                "Risk {} >= {} and evidence strength {} >= {} (rule score, not calibrated probability)",
                incident.risk,
                RESPONSE_RISK_THRESHOLD,
                incident.confidence,
                RESPONSE_CONFIDENCE_THRESHOLD
            ),
            http_status: None,
        }],
        state: Some(ResponseState::ResponseRequested),
    });
    incident.status = IncidentStatus::PendingVerification;
}

pub fn record(incident: &mut Incident, stage: &str, detail: String, http_status: Option<u16>) {
    if let Some(response) = incident.response.as_mut() {
        if stage == "GATEWAY_BLOCK_APPLIED" {
            response.state = Some(ResponseState::ResponseApplied);
        } else if stage == "VERIFICATION_REQUEST_SENT" {
            response.state = Some(ResponseState::VerificationPending);
        }
        response.proof.push(ResponseStep {
            timestamp: Utc::now(),
            stage: stage.into(),
            detail,
            http_status,
        });
    }
}

/// Only a verified gateway denial for this incident can close the incident.
pub fn finish(incident: &mut Incident, blocked: bool, http_status: u16, matching_incident: bool) {
    let Some(response) = incident.response.as_mut() else {
        return;
    };
    response.verified_at = Some(Utc::now());
    if blocked && http_status == 403 && matching_incident {
        incident.status = IncidentStatus::Contained;
        response.state = Some(ResponseState::Contained);
        response.result =
            "HTTP 403 from the lab gateway; matching denylist incident verified".into();
        response
            .actions
            .push("Lab gateway source block verified".into());
        response.proof.push(ResponseStep {
            timestamp: Utc::now(),
            stage: "CONTAINMENT_VERIFIED".into(),
            detail: response.result.clone(),
            http_status: Some(403),
        });
    } else {
        incident.status = IncidentStatus::ResponseFailed;
        response.state = Some(ResponseState::ResponseFailed);
        response.result = format!(
            "Verification failed: gateway returned HTTP {http_status}; human intervention required"
        );
        response.actions.push("Human intervention required".into());
        response.proof.push(ResponseStep {
            timestamp: Utc::now(),
            stage: "RESPONSE_FAILED".into(),
            detail: response.result.clone(),
            http_status: Some(http_status),
        });
    }
}

pub fn expire(incident: &mut Incident, reason: &str) {
    incident.status = IncidentStatus::Expired;
    if let Some(response) = incident.response.as_mut() {
        response.state = Some(ResponseState::Expired);
        response.proof.push(ResponseStep {
            timestamp: Utc::now(),
            stage: "EXPIRED".into(),
            detail: reason.to_string(),
            http_status: None,
        });
    }
}

pub fn rollback(incident: &mut Incident, reason: &str) {
    incident.status = IncidentStatus::RolledBack;
    if let Some(response) = incident.response.as_mut() {
        response.state = Some(ResponseState::RolledBack);
        response.proof.push(ResponseStep {
            timestamp: Utc::now(),
            stage: "ROLLED_BACK".into(),
            detail: reason.to_string(),
            http_status: None,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{baseline::Baseline, demo::scenario, tacg::correlate};
    #[test]
    fn only_actual_matching_403_contains() {
        let mut i = correlate(&scenario("multistage"), &Baseline::default()).remove(0);
        assert!(eligible(&i));
        begin(&mut i);
        assert_eq!(i.status, IncidentStatus::PendingVerification);
        finish(&mut i, true, 403, false);
        assert_eq!(i.status, IncidentStatus::ResponseFailed);
        let mut i = correlate(&scenario("multistage"), &Baseline::default()).remove(0);
        begin(&mut i);
        finish(&mut i, true, 403, true);
        assert_eq!(i.status, IncidentStatus::Contained);
        assert_eq!(
            i.response.as_ref().unwrap().state,
            Some(ResponseState::Contained)
        );
        assert_eq!(
            i.response.unwrap().proof.last().unwrap().stage,
            "CONTAINMENT_VERIFIED"
        );
    }

    #[test]
    fn test_approval_and_containment_states() {
        let mut i = correlate(&scenario("multistage"), &Baseline::default()).remove(0);
        request_approval(&mut i);
        assert_eq!(i.status, IncidentStatus::AwaitingApproval);
        assert_eq!(
            i.response.as_ref().unwrap().state,
            Some(ResponseState::AwaitingApproval)
        );

        begin(&mut i);
        assert_eq!(i.status, IncidentStatus::PendingVerification);
        assert_eq!(
            i.response.as_ref().unwrap().state,
            Some(ResponseState::ResponseRequested)
        );

        record(
            &mut i,
            "GATEWAY_BLOCK_APPLIED",
            "block created".into(),
            Some(200),
        );
        assert_eq!(
            i.response.as_ref().unwrap().state,
            Some(ResponseState::ResponseApplied)
        );

        record(
            &mut i,
            "VERIFICATION_REQUEST_SENT",
            "retry login".into(),
            None,
        );
        assert_eq!(
            i.response.as_ref().unwrap().state,
            Some(ResponseState::VerificationPending)
        );
    }

    #[test]
    fn test_response_expiry_and_rollback() {
        let mut i = correlate(&scenario("multistage"), &Baseline::default()).remove(0);
        begin(&mut i);
        finish(&mut i, true, 403, true);
        assert_eq!(i.status, IncidentStatus::Contained);

        expire(&mut i, "60-second lease expired");
        assert_eq!(i.status, IncidentStatus::Expired);
        assert_eq!(
            i.response.as_ref().unwrap().state,
            Some(ResponseState::Expired)
        );

        rollback(&mut i, "operator revoked block");
        assert_eq!(i.status, IncidentStatus::RolledBack);
        assert_eq!(
            i.response.as_ref().unwrap().state,
            Some(ResponseState::RolledBack)
        );
    }
}
