use crate::{
    event::SecurityEvent,
    incident::{Incident, IncidentStatus, ResponseRecord, RiskLevel},
};
use chrono::Utc;
pub fn respond(incident: &mut Incident) {
    if incident.response.is_some() {
        return;
    }
    let actions = if incident.severity == RiskLevel::Critical {
        vec![
            "Temporary source block in simulation".into(),
            "Session quarantine in simulation".into(),
            "Evidence snapshot".into(),
            "Administrator escalation".into(),
        ]
    } else {
        vec![
            "Increase monitoring in simulation".into(),
            "Preserve evidence".into(),
        ]
    };
    incident.response = Some(ResponseRecord {
        actions,
        responded_at: Utc::now(),
        verified_at: None,
        result: "Awaiting verification".into(),
        response_confidence: if incident.severity == RiskLevel::Critical {
            89
        } else {
            75
        },
        evidence: incident.events.iter().map(|e| e.id).collect(),
    });
    incident.status = IncidentStatus::PendingVerification;
}
pub fn verify(incident: &mut Incident, subsequent: &[SecurityEvent]) {
    let Some(r) = incident.response.as_mut() else {
        return;
    };
    let continued = subsequent.iter().any(|e| {
        e.source_ip == incident.source_ip
            && e.timestamp > r.responded_at
            && matches!(
                e.event_type,
                crate::event::EventType::FailedLogin
                    | crate::event::EventType::PrivilegeAction
                    | crate::event::EventType::UnusualNetworkActivity
                    | crate::event::EventType::UnauthorizedAccess
            )
    });
    r.verified_at = Some(Utc::now());
    if continued {
        incident.status = IncidentStatus::ResponseFailed;
        r.result =
            "Suspicious activity continued; simulated escalation and administrator notification"
                .into();
        r.actions.push("Escalate to administrator".into());
    } else {
        incident.status = IncidentStatus::Contained;
        r.result = "No subsequent suspicious source events observed in verification window".into();
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{baseline::Baseline, demo::scenario, event::EventType, tacg::correlate};
    #[test]
    fn response_and_verification() {
        let mut i = correlate(&scenario("multistage"), &Baseline::default()).remove(0);
        respond(&mut i);
        assert_eq!(i.status, IncidentStatus::PendingVerification);
        verify(&mut i, &[]);
        assert_eq!(i.status, IncidentStatus::Contained);
        let mut e = SecurityEvent::new(
            EventType::FailedLogin,
            Utc::now() + chrono::Duration::seconds(1),
            "10.0.0.70",
            "server-01",
        );
        e.username = Some("alice".into());
        verify(&mut i, &[e]);
        assert_eq!(i.status, IncidentStatus::ResponseFailed);
    }
}
