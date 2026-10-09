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
        (FailedLogin, PasswordAccepted) => 0.9,
        (PasswordAccepted, MfaFailure) => 0.7,
        (MfaFailure, MfaFailure) => 0.75,
        (MfaFailure, MfaSuccess) => 1.0,
        (MfaSuccess, SuccessfulLogin) => 0.9,
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
            | EventType::MfaFailure
            | EventType::MultiPortActivity
            | EventType::PrivilegeAction
            | EventType::UnusualNetworkActivity
            | EventType::UnauthorizedAccess
    )
}
/// Link consecutive failures for each account. A distributed detection must
/// span one connected path, rather than merely share a source counter.
fn failure_paths(events: &[SecurityEvent]) -> (Vec<GraphEdge>, usize, usize, f64) {
    let mut previous: HashMap<&str, &SecurityEvent> = HashMap::new();
    let mut edges = Vec::new();
    let failures: HashMap<Uuid, &SecurityEvent> = events
        .iter()
        .filter(|e| {
            e.event_type == EventType::FailedLogin && e.username.is_some() && e.hostname.is_some()
        })
        .map(|e| (e.id, e))
        .collect();
    for event in events
        .iter()
        .filter(|e| e.event_type == EventType::FailedLogin)
    {
        let Some(user) = event.username.as_deref() else {
            continue;
        };
        if event.hostname.is_none() {
            continue;
        }
        let prior = previous.insert(user, event);
        let connected = prior.is_some_and(|old| temporal_strength(old, event) >= 0.35);
        if let Some(old) = prior.filter(|_| connected) {
            let (entity, _) = entity_strength(old, event);
            edges.push(GraphEdge {
                from: old.id,
                to: event.id,
                strength: (0.6 * temporal_strength(old, event) + 0.4 * entity).min(1.0),
                reasons: vec![
                    "same source".into(),
                    "same username".into(),
                    "time-decayed authentication path".into(),
                ],
            });
        }
    }
    let mut adjacency: HashMap<Uuid, Vec<Uuid>> = HashMap::new();
    for edge in &edges {
        adjacency.entry(edge.from).or_default().push(edge.to);
        adjacency.entry(edge.to).or_default().push(edge.from);
    }
    let mut visited = HashSet::new();
    let mut longest_hosts = 0;
    let mut longest_failures = 0;
    let mut best_cross = 0.0;
    for id in failures.keys() {
        if !visited.insert(*id) {
            continue;
        }
        let mut pending = vec![*id];
        let mut count = 0;
        let mut hosts = HashSet::new();
        while let Some(node) = pending.pop() {
            count += 1;
            if let Some(host) = failures
                .get(&node)
                .and_then(|event| event.hostname.as_deref())
            {
                hosts.insert(host);
            }
            if let Some(neighbors) = adjacency.get(&node) {
                for neighbor in neighbors {
                    if visited.insert(*neighbor) {
                        pending.push(*neighbor);
                    }
                }
            }
        }
        let cross = if hosts.len() >= 3 && count >= 5 {
            1.0
        } else if hosts.len() >= 2 && count >= 4 {
            0.7
        } else {
            0.0
        };
        if cross > best_cross || (cross == best_cross && count > longest_failures) {
            best_cross = cross;
            longest_failures = count;
            longest_hosts = hosts.len();
        }
    }
    (edges, longest_failures, longest_hosts, best_cross)
}

fn ordered_attack_chain(events: &[SecurityEvent]) -> bool {
    events
        .iter()
        .filter(|e| e.event_type == EventType::SuccessfulLogin)
        .any(|login| {
            let Some(user) = login.username.as_deref() else {
                return false;
            };
            let failures = events
                .iter()
                .filter(|e| {
                    e.event_type == EventType::FailedLogin
                        && e.username.as_deref() == Some(user)
                        && e.timestamp < login.timestamp
                })
                .count();
            failures >= 2
                && events
                    .iter()
                    .filter(|e| {
                        e.event_type == EventType::PrivilegeAction
                            && e.username.as_deref() == Some(user)
                            && e.timestamp > login.timestamp
                    })
                    .any(|privilege| {
                        events.iter().any(|outbound| {
                            outbound.event_type == EventType::UnusualNetworkActivity
                                && outbound.timestamp > privilege.timestamp
                                && outbound.username.as_deref().is_none_or(|name| name == user)
                        })
                    })
        })
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
        // No candidate anchor in this source can produce an incident. Skip
        // the quadratic window search while keeping these events in baseline learning.
        if !all
            .iter()
            .any(|e| suspicious(e.event_type) || e.event_type == EventType::SuccessfulLogin)
        {
            continue;
        }
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
            if !group
                .iter()
                .any(|e| suspicious(e.event_type) || e.event_type == EventType::SuccessfulLogin)
            {
                continue;
            }
            let failures = group
                .iter()
                .filter(|e| e.event_type == EventType::FailedLogin)
                .count();
            let mfa_failures = group
                .iter()
                .filter(|e| e.event_type == EventType::MfaFailure)
                .count();
            let hosts: HashSet<_> = group
                .iter()
                .filter(|e| e.event_type == EventType::FailedLogin)
                .filter_map(|e| e.hostname.as_ref())
                .collect();
            let (failure_edges, path_failures, path_hosts, cross) = failure_paths(&group);
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
            for edge in failure_edges {
                if !edges
                    .iter()
                    .any(|existing| existing.from == edge.from && existing.to == edge.to)
                {
                    edges.push(edge);
                }
            }
            let types: HashSet<_> = group
                .iter()
                .map(|e| std::mem::discriminant(&e.event_type))
                .collect();
            let has = |t: EventType| group.iter().any(|e| e.event_type == t);
            let full_chain = ordered_attack_chain(&group);
            let mut per_account_host: HashMap<(&str, &str), usize> = HashMap::new();
            for event in group
                .iter()
                .filter(|e| e.event_type == EventType::FailedLogin)
            {
                if let (Some(user), Some(host)) =
                    (event.username.as_deref(), event.hostname.as_deref())
                {
                    *per_account_host.entry((user, host)).or_default() += 1;
                }
            }
            let brute = per_account_host.values().any(|count| *count >= 6);
            let distributed = cross >= 1.0;
            let repeated_mfa = group
                .iter()
                .filter(|e| e.event_type == EventType::MfaFailure)
                .any(|anchor_mfa| {
                    group
                        .iter()
                        .filter(|e| {
                            e.event_type == EventType::MfaFailure
                                && e.username == anchor_mfa.username
                                && (e.timestamp - anchor_mfa.timestamp).num_seconds().abs() <= 300
                        })
                        .count()
                        >= 3
                });
            let success_after_failures = group
                .iter()
                .filter(|e| e.event_type == EventType::SuccessfulLogin)
                .any(|login| {
                    group
                        .iter()
                        .filter(|e| {
                            e.event_type == EventType::FailedLogin
                                && e.username == login.username
                                && e.timestamp < login.timestamp
                                && (login.timestamp - e.timestamp).num_seconds() <= 600
                        })
                        .count()
                        >= 2
                });
            let first_group = group
                .first()
                .map(|e| e.timestamp)
                .unwrap_or(anchor.timestamp);
            let new_source_success = group.iter().any(|e| {
                if e.event_type != EventType::SuccessfulLogin {
                    return false;
                }
                let Some(user) = e.username.as_deref() else {
                    return false;
                };
                let previous: Vec<_> = events
                    .iter()
                    .filter(|old| {
                        old.event_type == EventType::SuccessfulLogin
                            && old.username.as_deref() == Some(user)
                            && old.timestamp < first_group
                    })
                    .collect();
                previous.len() >= 3 && !previous.iter().any(|old| old.source_ip == e.source_ip)
            });
            let familiar_auth = distributed
                && group
                    .iter()
                    .filter(|e| e.event_type == EventType::FailedLogin)
                    .all(|e| {
                        e.username
                            .as_deref()
                            .and_then(|user| baseline.users.get(user))
                            .is_some_and(|profile| {
                                profile.successful_logins >= 3
                                    && profile.source_ips.contains(&source)
                                    && e.hostname
                                        .as_ref()
                                        .is_some_and(|host| profile.hosts.contains(host))
                            })
                    });
            if !(brute
                || distributed
                || full_chain
                || repeated_mfa
                || success_after_failures
                || new_source_success
                || has(EventType::UnauthorizedAccess))
            {
                continue;
            }
            let rarity = if familiar_auth {
                0.3
            } else if full_chain {
                1.0
            } else if success_after_failures || repeated_mfa {
                0.9
            } else if new_source_success {
                0.7
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
            let transition_score = if familiar_auth {
                0.35
            } else if full_chain || success_after_failures {
                1.0
            } else if repeated_mfa {
                0.9
            } else if new_source_success {
                0.45
            } else if distributed {
                0.75
            } else if brute {
                0.65
            } else {
                transition_total / count.max(1.0)
            };
            let behaviour = baseline.deviation(&group).max(if familiar_auth {
                0.0
            } else if full_chain {
                0.8
            } else if success_after_failures || repeated_mfa {
                0.75
            } else if new_source_success {
                0.7
            } else if distributed {
                0.65
            } else if brute {
                0.5
            } else {
                0.3
            });
            let bonus = if familiar_auth {
                0.0
            } else if full_chain {
                25.0
            } else if success_after_failures {
                20.0
            } else if repeated_mfa {
                18.0
            } else if new_source_success {
                5.0
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
            if distributed {
                reasons.push(format!("connected failure path: {path_failures} attempts across {path_hosts} hosts for one account"));
            }
            if full_chain {
                reasons.push("ordered authentication → privilege → outbound attack chain".into());
            }
            if brute {
                reasons.push("repeated authentication failures in a 10-minute window".into());
            }
            if repeated_mfa {
                reasons.push(format!(
                    "{mfa_failures} failed MFA checks linked to the account and source"
                ));
            }
            if success_after_failures {
                reasons.push("completed login after nearby password failures".into());
            }
            if new_source_success {
                reasons.push(
                    "completed login from a source absent from established account history".into(),
                );
            }
            if edges.len() > 1 {
                reasons.push(format!("{} time-decayed graph links", edges.len()));
            }
            if types.len() > 3 {
                reasons.push("multiple security event types linked".into());
            }
            if familiar_auth {
                reasons.push("known account, source, and hosts; review before containment".into());
            } else {
                reasons.push("behavior differs from learned normal activity".into());
            }
            let severity = RiskLevel::from_score(score.final_risk);
            let target = group
                .iter()
                .find_map(|e| e.hostname.clone())
                .unwrap_or_else(|| "unknown host".into());
            let confidence = (70
                + if full_chain {
                    24
                } else if distributed || success_after_failures || repeated_mfa {
                    18
                } else if new_source_success {
                    8
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
                } else if success_after_failures {
                    "SUSPICIOUS SUCCESSFUL LOGIN".into()
                } else if repeated_mfa {
                    "REPEATED MFA FAILURES".into()
                } else if new_source_success {
                    "UNUSUAL SUCCESSFUL LOGIN".into()
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
    fn central_counter_is_insufficient_without_account_path() {
        let mut events = scenario("distributed");
        for (index, event) in events.iter_mut().enumerate() {
            event.username = Some(format!("user-{index}"));
        }
        assert_eq!(
            events
                .iter()
                .filter(|e| e.event_type == EventType::FailedLogin)
                .count(),
            5
        );
        assert!(correlate(&events, &Baseline::default()).is_empty());
    }
    #[test]
    fn distant_failures_do_not_form_distributed_path() {
        let mut events = scenario("distributed");
        let first = events[0].timestamp;
        for (index, event) in events.iter_mut().enumerate() {
            event.timestamp = first + chrono::Duration::seconds(index as i64 * 120);
        }
        assert!(correlate(&events, &Baseline::default()).is_empty());
    }
    #[test]
    fn familiar_account_path_alerts_without_automatic_block() {
        let failures = scenario("distributed");
        let source = failures[0].source_ip.as_deref().unwrap();
        let mut normal = Vec::new();
        for (index, host) in ["server-a", "server-b", "server-c"].iter().enumerate() {
            normal.push(auth_event(
                EventType::SuccessfulLogin,
                index as i64,
                source,
                host,
            ));
            normal.last_mut().unwrap().username = Some("admin".into());
        }
        let incident = correlate(&failures, &Baseline::learn(&normal)).remove(0);
        assert_eq!(incident.kind, "DISTRIBUTED AUTHENTICATION ATTACK");
        assert!(incident.risk < crate::response::RESPONSE_RISK_THRESHOLD);
    }
    #[test]
    fn reordered_stages_are_not_a_multi_stage_attack() {
        let mut events = scenario("multistage");
        let outbound = events
            .iter()
            .position(|e| e.event_type == EventType::UnusualNetworkActivity)
            .unwrap();
        events[outbound].timestamp = events[0].timestamp - chrono::Duration::seconds(1);
        assert!(
            correlate(&events, &Baseline::default())
                .iter()
                .all(|incident| incident.kind != "MULTI-STAGE INTRUSION")
        );
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
    fn auth_event(kind: EventType, second: i64, source: &str, host: &str) -> SecurityEvent {
        let mut e = SecurityEvent::new(
            kind,
            Utc::now() + chrono::Duration::seconds(second),
            source,
            host,
        );
        e.username = Some("demo".into());
        e.service = Some("portal".into());
        e
    }
    #[test]
    fn completed_login_after_failures_is_suspicious() {
        let events = vec![
            auth_event(EventType::FailedLogin, 0, "attacker-lab", "infra-a"),
            auth_event(EventType::FailedLogin, 5, "attacker-lab", "infra-b"),
            auth_event(EventType::PasswordAccepted, 10, "attacker-lab", "infra-c"),
            auth_event(EventType::MfaSuccess, 15, "attacker-lab", "infra-a"),
            auth_event(EventType::SuccessfulLogin, 16, "attacker-lab", "infra-a"),
        ];
        let incident = correlate(&events, &Baseline::default()).remove(0);
        assert_eq!(incident.kind, "SUSPICIOUS SUCCESSFUL LOGIN");
        assert!(incident.risk >= 85);
    }
    #[test]
    fn repeated_mfa_failures_are_detected() {
        let events: Vec<_> = (0..3)
            .map(|n| {
                auth_event(
                    EventType::MfaFailure,
                    n * 6,
                    "attacker-lab",
                    ["infra-a", "infra-b", "infra-c"][n as usize],
                )
            })
            .collect();
        let incident = correlate(&events, &Baseline::default()).remove(0);
        assert_eq!(incident.kind, "REPEATED MFA FAILURES");
        assert!(incident.risk >= 85);
    }
    #[test]
    fn replica_change_alone_is_not_suspicious() {
        let events: Vec<_> = (0..3)
            .map(|n| {
                auth_event(
                    EventType::SuccessfulLogin,
                    n * 12,
                    "normal-client",
                    ["infra-a", "infra-b", "infra-c"][n as usize],
                )
            })
            .collect();
        assert!(correlate(&events, &Baseline::learn(&events)).is_empty());
    }
}
