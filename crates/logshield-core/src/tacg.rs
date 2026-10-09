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

/// Configuration flags controlling which TACG capabilities are active.
/// Used for controlled ablation studies where exactly one feature is disabled at a time.
#[derive(Debug, Clone)]
pub struct CorrelationConfig {
    /// Enable temporal edge decay between events (exp(-Δt/τ)).
    /// When disabled, all edges within the window receive uniform weight 1.0.
    pub temporal_decay: bool,
    /// Enable graph-path-based failure connectivity for distributed detection.
    /// When disabled, distributed detection uses flat failure counts instead of
    /// connected same-account paths.
    pub graph_edges: bool,
    /// Enable behavioral baseline familiarity discounting.
    /// When disabled, all activity is treated as unfamiliar (cold-start behavior).
    pub baseline_familiarity: bool,
    /// Enable identity-anchored correlation (Pass 2) for rotating-source attacks.
    /// When disabled, only source-anchored (Pass 1) clustering is performed.
    pub identity_correlation: bool,
}

impl Default for CorrelationConfig {
    fn default() -> Self {
        Self {
            temporal_decay: true,
            graph_edges: true,
            baseline_familiarity: true,
            identity_correlation: true,
        }
    }
}

impl CorrelationConfig {
    /// Full TACG — all capabilities enabled.
    pub fn full() -> Self {
        Self::default()
    }
    /// Ablation: disable only graph edge connectivity.
    pub fn no_graph_edges() -> Self {
        Self {
            graph_edges: false,
            ..Self::default()
        }
    }
    /// Ablation: disable only baseline familiarity discounting.
    pub fn no_baseline() -> Self {
        Self {
            baseline_familiarity: false,
            ..Self::default()
        }
    }
    /// Ablation: disable only temporal decay (uniform edge weights).
    pub fn no_temporal_decay() -> Self {
        Self {
            temporal_decay: false,
            ..Self::default()
        }
    }
    /// Ablation: disable only identity-anchored cross-source correlation.
    pub fn no_identity_correlation() -> Self {
        Self {
            identity_correlation: false,
            ..Self::default()
        }
    }
}

pub fn temporal_strength(a: &SecurityEvent, b: &SecurityEvent) -> f64 {
    let d = (a.timestamp - b.timestamp).num_seconds().unsigned_abs() as f64;
    (-d / TAU).exp()
}
/// Config-aware temporal strength: returns uniform 1.0 when decay is disabled.
fn temporal_cfg(a: &SecurityEvent, b: &SecurityEvent, config: &CorrelationConfig) -> f64 {
    if config.temporal_decay {
        temporal_strength(a, b)
    } else {
        let d = (a.timestamp - b.timestamp).num_seconds().unsigned_abs();
        if d <= WINDOW_SECS as u64 { 1.0 } else { 0.0 }
    }
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
fn failure_paths(
    events: &[SecurityEvent],
    config: &CorrelationConfig,
) -> (Vec<GraphEdge>, usize, usize, f64) {
    let failures: HashMap<Uuid, &SecurityEvent> = events
        .iter()
        .filter(|e| {
            e.event_type == EventType::FailedLogin && e.username.is_some() && e.hostname.is_some()
        })
        .map(|e| (e.id, e))
        .collect();

    if !config.graph_edges {
        // Ablation: flat failure counting across the cluster without graph path connectivity.
        // Evaluates flat failure count and host dispersion without requiring a same-account connected graph path.
        let failure_count = events
            .iter()
            .filter(|e| e.event_type == EventType::FailedLogin)
            .count();
        let hosts: HashSet<&str> = events
            .iter()
            .filter(|e| e.event_type == EventType::FailedLogin)
            .filter_map(|e| e.hostname.as_deref())
            .collect();
        let cross = if hosts.len() >= 3 && failure_count >= 5 {
            1.0
        } else if hosts.len() >= 2 && failure_count >= 4 {
            0.7
        } else {
            0.0
        };
        return (Vec::new(), failure_count, hosts.len(), cross);
    }

    // Full graph path construction
    let mut previous: HashMap<&str, &SecurityEvent> = HashMap::new();
    let mut edges = Vec::new();
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
        let connected = prior.is_some_and(|old| temporal_cfg(old, event, config) >= 0.35);
        if let Some(old) = prior.filter(|_| connected) {
            let (entity, _) = entity_strength(old, event);
            edges.push(GraphEdge {
                from: old.id,
                to: event.id,
                strength: (0.6 * temporal_cfg(old, event, config) + 0.4 * entity).min(1.0),
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
/// Returns true if all authentication events in the group belong to an established
/// user profile where the source IP and targeted hosts are present in the historical baseline.
fn is_familiar_auth(group: &[SecurityEvent], baseline: &Baseline) -> bool {
    let auth_events: Vec<_> = group
        .iter()
        .filter(|e| {
            matches!(
                e.event_type,
                EventType::FailedLogin
                    | EventType::SuccessfulLogin
                    | EventType::MfaFailure
                    | EventType::PasswordAccepted
            )
        })
        .collect();
    if auth_events.is_empty() {
        return false;
    }
    auth_events.iter().all(|e| {
        e.username
            .as_deref()
            .and_then(|user| baseline.users.get(user))
            .is_some_and(|profile| {
                profile.successful_logins >= 3
                    && e.source_ip
                        .as_deref()
                        .is_some_and(|ip| profile.source_ips.contains(ip))
                    && e.hostname
                        .as_deref()
                        .is_some_and(|host| profile.hosts.contains(host))
            })
    })
}

fn evaluate_cluster(
    group: &[SecurityEvent],
    baseline: &Baseline,
    anchor_source: Option<String>,
    config: &CorrelationConfig,
) -> Option<Incident> {
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
    let sources: HashSet<_> = group
        .iter()
        .filter_map(|e| e.source_ip.as_deref())
        .collect();
    let (failure_edges, path_failures, path_hosts, cross) = failure_paths(group, config);
    let mut edges = Vec::new();
    let mut temporal_total = 0.0;
    let mut entity_total = 0.0;
    let mut transition_total = 0.0;
    let mut count = 0.0;
    for pair in group.windows(2) {
        let a = &pair[0];
        let b = &pair[1];
        let temporal = temporal_cfg(a, b, config);
        let (entity, mut reasons) = entity_strength(a, b);
        let tr = transition(a.event_type, b.event_type);
        if tr > 0.0 {
            reasons.push(format!("{:?} → {:?}", a.event_type, b.event_type));
        }
        if config.graph_edges && temporal > 0.1 && entity > 0.0 {
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
    if config.graph_edges {
        for edge in failure_edges {
            if !edges
                .iter()
                .any(|existing| existing.from == edge.from && existing.to == edge.to)
            {
                edges.push(edge);
            }
        }
    }
    let types: HashSet<_> = group
        .iter()
        .map(|e| std::mem::discriminant(&e.event_type))
        .collect();
    let has = |t: EventType| group.iter().any(|e| e.event_type == t);
    let full_chain = ordered_attack_chain(group);
    let mut per_account_host: HashMap<(&str, &str), usize> = HashMap::new();
    for event in group
        .iter()
        .filter(|e| e.event_type == EventType::FailedLogin)
    {
        if let (Some(user), Some(host)) = (event.username.as_deref(), event.hostname.as_deref()) {
            *per_account_host.entry((user, host)).or_default() += 1;
        }
    }
    let brute = per_account_host.values().any(|count| *count >= 6);
    let distributed = cross >= 1.0;
    let is_rotating_sources = sources.len() >= 3 && path_failures >= 4;

    let distinct_failed_users: HashSet<&str> = group
        .iter()
        .filter(|e| e.event_type == EventType::FailedLogin)
        .filter_map(|e| e.username.as_deref())
        .collect();
    let spray = distinct_failed_users.len() >= 6 && failures >= 6;

    let familiar_auth = if config.baseline_familiarity {
        is_familiar_auth(group, baseline)
    } else {
        false
    };

    // If a password spray is identified, connect consecutive failures from the same source
    if config.graph_edges && spray && !familiar_auth {
        let failure_events: Vec<_> = group
            .iter()
            .filter(|e| e.event_type == EventType::FailedLogin)
            .collect();
        for pair in failure_events.windows(2) {
            let a = pair[0];
            let b = pair[1];
            let temporal = temporal_cfg(a, b, config);
            if temporal >= 0.20 && !edges.iter().any(|e| e.from == a.id && e.to == b.id) {
                edges.push(GraphEdge {
                    from: a.id,
                    to: b.id,
                    strength: (0.6 * temporal + 0.4).min(1.0),
                    reasons: vec![
                        "same source".into(),
                        "cross-account password spray probe".into(),
                    ],
                });
            }
        }
    }

    let repeated_mfa = group
        .iter()
        .filter(|e| e.event_type == EventType::MfaFailure)
        .any(|anchor_mfa| {
            let mfa_in_window = group
                .iter()
                .filter(|e| {
                    e.event_type == EventType::MfaFailure
                        && e.username == anchor_mfa.username
                        && (e.timestamp - anchor_mfa.timestamp).num_seconds().abs() <= 300
                })
                .count();
            let mfa_hosts: HashSet<_> = group
                .iter()
                .filter(|e| {
                    e.event_type == EventType::MfaFailure && e.username == anchor_mfa.username
                })
                .filter_map(|e| e.hostname.as_deref())
                .collect();
            if familiar_auth {
                // For established familiar users on a single host, up to 3 MFA retries is human error.
                // Attack patterns exhibit rapid push fatigue (>= 4 retries) or cross-host probing.
                mfa_in_window >= 4 || (mfa_in_window >= 3 && mfa_hosts.len() > 1)
            } else {
                mfa_in_window >= 3
            }
        });

    let success_after_failures = group
        .iter()
        .filter(|e| e.event_type == EventType::SuccessfulLogin)
        .any(|login| {
            let failures_before = group
                .iter()
                .filter(|e| {
                    e.event_type == EventType::FailedLogin
                        && e.username == login.username
                        && e.timestamp < login.timestamp
                        && (login.timestamp - e.timestamp).num_seconds() <= 600
                })
                .count();
            if familiar_auth {
                // For familiar users on known hosts, 1-2 password typos is routine.
                // Attack patterns require repeated guessing (>= 4) or cross-host failures before success.
                failures_before >= 4 || (failures_before >= 2 && hosts.len() > 1)
            } else {
                failures_before >= 2
            }
        });

    let new_source_success = group.iter().any(|e| {
        if e.event_type != EventType::SuccessfulLogin {
            return false;
        }
        let Some(user) = e.username.as_deref() else {
            return false;
        };
        baseline.users.get(user).is_some_and(|p| {
            p.successful_logins >= 3
                && e.source_ip
                    .as_ref()
                    .is_some_and(|ip| !p.source_ips.contains(ip))
        })
    });

    let is_spray_attack = spray && !familiar_auth;

    if !(brute
        || distributed
        || is_rotating_sources
        || is_spray_attack
        || full_chain
        || repeated_mfa
        || success_after_failures
        || (new_source_success && failures > 0)
        || has(EventType::UnauthorizedAccess))
    {
        return None;
    }

    let rarity = if familiar_auth {
        0.3
    } else if full_chain {
        1.0
    } else if success_after_failures || repeated_mfa {
        0.9
    } else if is_rotating_sources || is_spray_attack {
        0.85
    } else if distributed {
        0.8
    } else if brute {
        0.75
    } else if new_source_success {
        0.65
    } else {
        0.60
    };
    let temporal = if config.graph_edges {
        if count > 0.0 {
            temporal_total / count
        } else {
            0.0
        }
    } else {
        0.5
    };
    let entity = if config.graph_edges {
        if count > 0.0 {
            entity_total / count
        } else {
            0.0
        }
    } else {
        0.5
    };
    let transition_score = if familiar_auth {
        0.35
    } else if full_chain || success_after_failures {
        1.0
    } else if repeated_mfa {
        0.9
    } else if is_rotating_sources || distributed || is_spray_attack {
        0.75
    } else if brute {
        0.65
    } else if new_source_success {
        0.45
    } else {
        transition_total / count.max(1.0)
    };
    let base_dev = if config.baseline_familiarity {
        baseline.deviation(group)
    } else {
        0.5
    };
    let behaviour = base_dev.max(if familiar_auth {
        0.0
    } else if full_chain {
        0.8
    } else if success_after_failures || repeated_mfa {
        0.75
    } else if is_rotating_sources || is_spray_attack {
        0.70
    } else if distributed {
        0.65
    } else if brute || new_source_success {
        0.50
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
    } else if is_rotating_sources {
        15.0
    } else if is_spray_attack {
        14.0
    } else if distributed {
        8.0
    } else if brute {
        12.0
    } else if new_source_success {
        8.0
    } else {
        0.0
    };
    let score = ScoreBreakdown::calculate(
        rarity,
        temporal,
        entity,
        transition_score,
        if is_rotating_sources || is_spray_attack {
            1.0
        } else {
            cross
        },
        behaviour,
        bonus,
    );
    let source_str = anchor_source
        .or_else(|| group.first().and_then(|e| e.source_ip.clone()))
        .unwrap_or_else(|| "unknown".into());
    let mut reasons = Vec::new();
    if failures > 0 {
        reasons.push(format!("{failures} failed logins across cluster"));
    }
    if hosts.len() > 1 {
        reasons.push(format!("activity spans {} distinct hosts", hosts.len()));
    }
    if is_rotating_sources {
        reasons.push(format!(
            "rotating source IPs: {} distinct sources targeting single identity",
            sources.len()
        ));
    }
    if is_spray_attack {
        reasons.push(format!(
            "password spray attack: {failures} failures across {} distinct targeted accounts",
            distinct_failed_users.len()
        ));
    }
    if distributed {
        reasons.push(format!(
            "connected failure path: {path_failures} attempts across {path_hosts} hosts for one account"
        ));
    }
    if full_chain {
        reasons.push("ordered authentication → privilege → outbound attack chain".into());
    }
    if brute {
        reasons.push("repeated authentication failures in a 10-minute window".into());
    }
    if repeated_mfa {
        reasons.push(format!(
            "{mfa_failures} failed MFA checks linked to the account"
        ));
    }
    if success_after_failures {
        reasons.push("completed login after nearby password failures".into());
    }
    if new_source_success {
        reasons
            .push("completed login from a source absent from established account history".into());
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
        } else if distributed
            || is_rotating_sources
            || is_spray_attack
            || success_after_failures
            || repeated_mfa
        {
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
    Some(Incident {
        id: Uuid::new_v4(),
        created_at: Utc::now(),
        source_ip: Some(source_str),
        target,
        kind: if distributed || is_rotating_sources {
            "DISTRIBUTED AUTHENTICATION ATTACK".into()
        } else if is_spray_attack {
            "PASSWORD SPRAY ATTACK".into()
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
        events: group.to_vec(),
        edges,
        response: None,
    })
}

pub fn correlate(events: &[SecurityEvent], baseline: &Baseline) -> Vec<Incident> {
    correlate_with_config(events, baseline, &CorrelationConfig::full())
}

pub fn correlate_with_config(
    events: &[SecurityEvent],
    baseline: &Baseline,
    config: &CorrelationConfig,
) -> Vec<Incident> {
    let mut sorted: Vec<_> = events
        .iter()
        .filter(|e| e.hostname.as_deref() != Some("gateway"))
        .cloned()
        .collect();
    sorted.sort_by_key(|e| e.timestamp);
    let mut groups: HashMap<String, Vec<SecurityEvent>> = HashMap::new();
    for e in &sorted {
        if let Some(ip) = &e.source_ip {
            groups.entry(ip.clone()).or_default().push(e.clone());
        }
    }
    let mut incidents = Vec::new();
    let mut claimed_ids = HashSet::new();

    // Pass 1: Source-anchored correlation (single-source scanning, brute force, multi-stage chains)
    for (source, all) in groups {
        if !all
            .iter()
            .any(|e| suspicious(e.event_type) || e.event_type == EventType::SuccessfulLogin)
        {
            continue;
        }
        let mut used = HashSet::new();
        for anchor in &all {
            if used.contains(&anchor.id) || claimed_ids.contains(&anchor.id) {
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
            if let Some(incident) = evaluate_cluster(&group, baseline, Some(source.clone()), config)
            {
                for e in &incident.events {
                    used.insert(e.id);
                    claimed_ids.insert(e.id);
                }
                incidents.push(incident);
            }
        }
    }

    // Pass 2: Identity-anchored correlation (cross-source attacks targeting single identities, rotating IPs)
    if config.identity_correlation {
        let mut identity_groups: HashMap<String, Vec<SecurityEvent>> = HashMap::new();
        for e in &sorted {
            if claimed_ids.contains(&e.id) {
                continue;
            }
            let matches = match &e.username {
                Some(user) => {
                    !user.is_empty()
                        && (suspicious(e.event_type) || e.event_type == EventType::SuccessfulLogin)
                }
                None => false,
            };
            if matches {
                identity_groups
                    .entry(e.username.clone().unwrap())
                    .or_default()
                    .push(e.clone());
            }
        }
        for (_user, all_user) in identity_groups {
            let unique_sources: HashSet<_> = all_user
                .iter()
                .filter_map(|e| e.source_ip.as_deref())
                .collect();
            if unique_sources.len() < 2 {
                continue;
            }
            let mut used = HashSet::new();
            for anchor in &all_user {
                if used.contains(&anchor.id) || claimed_ids.contains(&anchor.id) {
                    continue;
                }
                let group: Vec<_> = all_user
                    .iter()
                    .filter(|e| {
                        (e.timestamp - anchor.timestamp).num_seconds().abs() <= WINDOW_SECS
                            && !used.contains(&e.id)
                            && !claimed_ids.contains(&e.id)
                    })
                    .cloned()
                    .collect();
                let sources_in_group: HashSet<_> = group
                    .iter()
                    .filter_map(|e| e.source_ip.as_deref())
                    .collect();
                if sources_in_group.len() < 2 {
                    continue;
                }
                if let Some(incident) = evaluate_cluster(&group, baseline, None, config) {
                    for e in &incident.events {
                        used.insert(e.id);
                        claimed_ids.insert(e.id);
                    }
                    incidents.push(incident);
                }
            }
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
    #[test]
    fn ablation_no_graph_edges_produces_empty_edges() {
        let events = scenario("distributed");
        let incidents = correlate_with_config(
            &events,
            &Baseline::default(),
            &CorrelationConfig::no_graph_edges(),
        );
        assert!(!incidents.is_empty());
        assert!(
            incidents[0].edges.is_empty(),
            "Graph-disabled TACG must not construct graph edges"
        );
    }
    #[test]
    fn ablation_no_baseline_does_not_discount_familiar_activity() {
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
        let baseline = Baseline::learn(&normal);
        // With baseline enabled, familiar activity has lower risk
        let with_base =
            correlate_with_config(&failures, &baseline, &CorrelationConfig::full()).remove(0);
        // With baseline disabled, no discounting occurs, risk is higher
        let without_base =
            correlate_with_config(&failures, &baseline, &CorrelationConfig::no_baseline())
                .remove(0);
        assert!(without_base.risk >= with_base.risk);
    }
    #[test]
    fn ablation_no_identity_correlation_ignores_cross_source_accounts() {
        let mut events = Vec::new();
        for i in 0..5 {
            let mut e = auth_event(
                EventType::FailedLogin,
                i * 10,
                &format!("198.51.100.{}", i + 1),
                "server-a",
            );
            e.username = Some("target_user".into());
            events.push(e);
        }
        let with_ident =
            correlate_with_config(&events, &Baseline::default(), &CorrelationConfig::full());
        assert!(
            !with_ident.is_empty(),
            "Full TACG must detect rotating sources"
        );
        let without_ident = correlate_with_config(
            &events,
            &Baseline::default(),
            &CorrelationConfig::no_identity_correlation(),
        );
        assert!(
            without_ident.is_empty(),
            "Ablation without identity correlation must ignore cross-source accounts"
        );
    }
    #[test]
    fn password_spray_attack_detected() {
        let mut events = Vec::new();
        let spray_ip = "198.51.100.99";
        for i in 0..7 {
            let mut e = auth_event(
                EventType::FailedLogin,
                i * 5,
                spray_ip,
                if i % 2 == 0 { "infra-a" } else { "infra-b" },
            );
            e.username = Some(format!("user_{}", i));
            events.push(e);
        }
        let incidents = correlate(&events, &Baseline::default());
        assert!(!incidents.is_empty(), "Password spray must be detected");
        assert_eq!(incidents[0].kind, "PASSWORD SPRAY ATTACK");
        assert!(incidents[0].risk >= 70);
    }
    #[test]
    fn temporal_decay_distinguishes_rapid_burst_from_slow_drift() {
        // Slow sporadic failures spaced 140s apart (total span: 560s within 600s window)
        // With tau = 90s, exp(-140/90) = 0.21 < 0.35, so edges decay below threshold.
        // Full TACG does NOT link them into a connected attack path.
        // However, no_temporal_decay treats every gap <= 600s as 1.0, falsely linking them.
        let mut slow_events = Vec::new();
        for i in 0..5 {
            let mut e = auth_event(
                EventType::FailedLogin,
                i * 140,
                "192.168.1.50",
                ["infra-a", "infra-b", "infra-c", "infra-a", "infra-b"][i as usize],
            );
            e.username = Some("alice".into());
            slow_events.push(e);
        }
        let full_incidents = correlate_with_config(
            &slow_events,
            &Baseline::default(),
            &CorrelationConfig::full(),
        );
        assert!(
            full_incidents.is_empty(),
            "Full TACG must decay slow sporadic failures below connection threshold"
        );

        let no_decay_incidents = correlate_with_config(
            &slow_events,
            &Baseline::default(),
            &CorrelationConfig::no_temporal_decay(),
        );
        assert!(
            !no_decay_incidents.is_empty(),
            "Ablated TACG without temporal decay falsely links slow drift into an attack"
        );
    }
}
