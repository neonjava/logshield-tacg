use crate::{
    baseline::Baseline,
    event::{EventType, SecurityEvent},
    incident::{GraphEdge, Incident, IncidentStatus, RiskLevel},
    risk::ScoreBreakdown,
};
use chrono::Utc;
use std::collections::{HashMap, HashSet};
use uuid::Uuid;
const WINDOW_SECS: i64 = 600;
const TAU: f64 = 90.0;

pub fn temporal_strength(a: &SecurityEvent, b: &SecurityEvent) -> f64 {
    let d = (a.timestamp - b.timestamp).num_seconds().unsigned_abs() as f64;
    (-d / TAU).exp()
}
pub fn entity_strength(a: &SecurityEvent, b: &SecurityEvent) -> (f64, Vec<String>) {
    let mut n: f64 = 0.0;
    let mut reasons = Vec::new();
    for (label, x, y, weight) in [
        ("same source", &a.source_ip, &b.source_ip, 0.55),
        (
            "same destination",
            &a.destination_ip,
            &b.destination_ip,
            0.15,
        ),
        ("same username", &a.username, &b.username, 0.25),
        ("same host", &a.hostname, &b.hostname, 0.25),
        ("same service", &a.service, &b.service, 0.10),
        ("same request", &a.request_id, &b.request_id, 0.10),
    ] {
        if x.is_some() && x == y {
            n += weight;
            reasons.push(label.into());
        }
    }
    (n.min(1.0), reasons)
}
fn transition(a: EventType, b: EventType) -> f64 {
    use EventType::*;
    match (a, b) {
        (FailedLogin, FailedLogin) => 0.55,
        (FailedLogin, SuccessfulLogin) => 1.0,
        (SuccessfulLogin, PrivilegeAction) => 1.0,
        (PrivilegeAction, UnusualNetworkActivity) => 1.0,
        (MultiPortActivity, FailedLogin) => 0.85,
        (Connection, MultiPortActivity) => 0.65,
        (FailedLogin, UnauthorizedAccess) => 0.7,
        _ => 0.0,
    }
}
fn suspicious(t: EventType) -> bool {
    matches!(
        t,
        EventType::FailedLogin
            | EventType::MultiPortActivity
            | EventType::PrivilegeAction
            | EventType::UnusualNetworkActivity
            | EventType::UnauthorizedAccess
    )
}
pub fn correlate(events: &[SecurityEvent], baseline: &Baseline) -> Vec<Incident> {
    let mut sorted: Vec<_> = events
        .iter()
        .filter(|e| e.hostname.as_deref() != Some("gateway"))
        .cloned()
        .collect();
    sorted.sort_by_key(|e| e.timestamp);
    let mut groups: HashMap<String, Vec<SecurityEvent>> = HashMap::new();
    for e in sorted {
        if let Some(ip) = &e.source_ip {
            groups.entry(ip.clone()).or_default().push(e);
        }
    }
    let mut incidents = Vec::new();
    for (source, all) in groups {
        let mut used = HashSet::new();
        for anchor in &all {
            if used.contains(&anchor.id) {
                continue;
            }
            let group: Vec<_> = all
                .iter()
                .filter(|e| {
                    (e.timestamp - anchor.timestamp).num_seconds().abs() <= WINDOW_SECS
                        && !used.contains(&e.id)
                })
                .cloned()
                .collect();
            if !group.iter().any(|e| suspicious(e.event_type)) {
                continue;
            }
            let failures = group
                .iter()
                .filter(|e| e.event_type == EventType::FailedLogin)
                .count();
            let hosts: HashSet<_> = group
                .iter()
                .filter(|e| e.event_type == EventType::FailedLogin)
                .filter_map(|e| e.hostname.as_ref())
                .collect();
            let cross = if hosts.len() >= 3 && failures >= 5 {
                1.0
            } else if hosts.len() >= 2 && failures >= 4 {
                0.7
            } else {
                0.0
            };
            let mut edges = Vec::new();
            let mut temporal_total = 0.0;
            let mut entity_total = 0.0;
            let mut transition_total = 0.0;
            let mut count = 0.0;
            for pair in group.windows(2) {
                let a = &pair[0];
                let b = &pair[1];
                let temporal = temporal_strength(a, b);
                let (entity, mut reasons) = entity_strength(a, b);
                let tr = transition(a.event_type, b.event_type);
                if tr > 0.0 {
                    reasons.push(format!("{:?} → {:?}", a.event_type, b.event_type));
                }
                if temporal > 0.1 && entity > 0.0 {
                    edges.push(GraphEdge {
                        from: a.id,
                        to: b.id,
                        strength: (0.4 * temporal + 0.4 * entity + 0.2 * tr).min(1.0),
                        reasons,
                    });
                }
                temporal_total += temporal;
                entity_total += entity;
                transition_total += tr;
                count += 1.0;
            }
            let types: HashSet<_> = group
                .iter()
                .map(|e| std::mem::discriminant(&e.event_type))
                .collect();
            let has = |t: EventType| group.iter().any(|e| e.event_type == t);
            let full_chain = failures >= 2
                && has(EventType::SuccessfulLogin)
                && has(EventType::PrivilegeAction)
                && has(EventType::UnusualNetworkActivity);
            let brute = failures >= 6;
            let distributed = cross >= 1.0;
            if !(brute || distributed || full_chain || has(EventType::UnauthorizedAccess)) {
                continue;
            }
            let rarity = if full_chain {
                1.0
            } else if distributed {
                0.8
            } else if brute {
                0.75
            } else {
                0.65
            };
            let temporal = if count > 0.0 {
                temporal_total / count
            } else {
                0.0
            };
            let entity = if count > 0.0 {
                entity_total / count
            } else {
                0.0
            };
            let transition_score = if full_chain {
                1.0
            } else if distributed {
                0.75
            } else if brute {
                0.65
            } else {
                transition_total / count.max(1.0)
            };
            let behaviour = baseline.deviation(&group).max(if full_chain {
                0.8
            } else if distributed {
                0.65
            } else if brute {
                0.5
            } else {
                0.3
            });
            let bonus = if full_chain {
                25.0
            } else if distributed {
                8.0
            } else if brute {
                12.0
            } else {
                0.0
            };
            let score = ScoreBreakdown::calculate(
                rarity,
                temporal,
                entity,
                transition_score,
                cross,
                behaviour,
                bonus,
            );
            let mut reasons = Vec::new();
            if failures > 0 {
                reasons.push(format!("{failures} failed logins from {source}"));
            }
            if hosts.len() > 1 {
                reasons.push(format!("same source across {} hosts", hosts.len()));
            }
            if full_chain {
                reasons.push("ordered authentication → privilege → outbound attack chain".into());
            }
            if brute {
                reasons.push("repeated authentication failures in a 10-minute window".into());
            }
            if edges.len() > 1 {
                reasons.push(format!("{} time-decayed graph links", edges.len()));
            }
            if types.len() > 3 {
                reasons.push("multiple security event types linked".into());
            }
            reasons.push("behavior differs from learned normal activity".into());
            let severity = RiskLevel::from_score(score.final_risk);
            let target = group
                .iter()
                .find_map(|e| e.hostname.clone())
                .unwrap_or_else(|| "unknown host".into());
            let confidence = (70
                + if full_chain {
                    24
                } else if distributed {
                    18
                } else {
                    12
                })
            .min(99);
            let recommended_actions = match severity {
                RiskLevel::Critical => vec![
                    "Block source at the lab gateway for 60 seconds".into(),
                    "Verify the block with a real lab request".into(),
                    "Preserve event evidence".into(),
                ],
                RiskLevel::High => vec!["Recommend containment".into(), "Preserve evidence".into()],
                _ => vec![
                    "Increase monitoring".into(),
                    "Review authentication activity".into(),
                ],
            };
            for e in &group {
                used.insert(e.id);
            }
            incidents.push(Incident {
                id: Uuid::new_v4(),
                created_at: Utc::now(),
                source_ip: Some(source.clone()),
                target,
                kind: if distributed {
                    "DISTRIBUTED AUTHENTICATION ATTACK".into()
                } else if full_chain {
                    "MULTI-STAGE INTRUSION".into()
                } else if brute {
                    "BRUTE FORCE AUTHENTICATION".into()
                } else {
                    "UNAUTHORIZED ACCESS".into()
                },
                risk: score.final_risk,
                severity,
                status: IncidentStatus::Active,
                confidence,
                score,
                reasons,
                recommended_actions,
                events: group,
                edges,
                response: None,
            });
        }
    }
    incidents.sort_by_key(|a| std::cmp::Reverse(a.risk));
    incidents
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::demo::scenario;
    #[test]
    fn time_decay() {
        let x = scenario("multistage");
        assert!(temporal_strength(&x[0], &x[1]) > 0.9);
    }
    #[test]
    fn normal_is_clean() {
        let e = scenario("normal");
        assert!(correlate(&e, &Baseline::learn(&e)).is_empty());
    }
    #[test]
    fn distributed_crosses_hosts() {
        let e = scenario("distributed");
        let i = correlate(&e, &Baseline::default());
        assert_eq!(i.len(), 1);
        assert!(i[0].risk >= 70);
        assert_eq!(i[0].events.len(), 5);
    }
    #[test]
    fn multistage_is_critical() {
        let e = scenario("multistage");
        let i = correlate(&e, &Baseline::default());
        assert_eq!(i.len(), 1);
        assert_eq!(i[0].severity, RiskLevel::Critical);
        assert_eq!(i[0].events.len(), 7);
        assert!(i[0].edges.len() >= 6);
    }
    #[test]
    fn five_event_lab_chain_is_critical() {
        let all = scenario("multistage");
        let events = all.into_iter().skip(2).collect::<Vec<_>>();
        let incident = correlate(&events, &Baseline::default()).remove(0);
        assert_eq!(incident.kind, "MULTI-STAGE INTRUSION");
        assert!(incident.risk >= 85);
        assert_eq!(incident.events.len(), 5);
    }
    #[test]
    fn brute_force_detected() {
        let e = scenario("bruteforce");
        assert!(!correlate(&e, &Baseline::default()).is_empty());
    }
}
