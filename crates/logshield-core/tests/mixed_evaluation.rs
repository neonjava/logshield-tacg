//! Deterministic mixed-traffic regression study. These are authored cases, not field data.
use chrono::{DateTime, Duration, Utc};
use logshield_core::{
    baseline::Baseline,
    event::{EventType, SecurityEvent},
    tacg::correlate,
};
use std::collections::{HashMap, HashSet};

struct Case {
    name: &'static str,
    malicious: bool,
    history: Vec<SecurityEvent>,
    events: Vec<SecurityEvent>,
}
#[derive(Default)]
struct Metrics {
    tp: usize,
    fp: usize,
    tn: usize,
    fn_: usize,
    delays: Vec<i64>,
    benign_critical: usize,
}
impl Metrics {
    fn record(&mut self, malicious: bool, alerted: bool, critical: bool, delay: Option<i64>) {
        match (malicious, alerted) {
            (true, true) => self.tp += 1,
            (true, false) => self.fn_ += 1,
            (false, true) => self.fp += 1,
            (false, false) => self.tn += 1,
        }
        if !malicious && critical {
            self.benign_critical += 1;
        }
        if let Some(delay) = delay {
            self.delays.push(delay);
        }
    }
    fn summary(&self) -> String {
        let precision = self.tp as f64 / (self.tp + self.fp).max(1) as f64;
        let recall = self.tp as f64 / (self.tp + self.fn_).max(1) as f64;
        let fpr = self.fp as f64 / (self.fp + self.tn).max(1) as f64;
        let delay = if self.delays.is_empty() {
            String::from("n/a")
        } else {
            let mut delays = self.delays.clone();
            delays.sort_unstable();
            format!("{}s", delays[delays.len() / 2])
        };
        format!(
            "TP={} FP={} TN={} FN={} precision={precision:.2} recall={recall:.2} FPR={fpr:.2} median_detection_delay={delay} benign_critical={}",
            self.tp, self.fp, self.tn, self.fn_, self.benign_critical
        )
    }
}
fn time(second: i64) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339("2026-10-10T10:00:00Z")
        .unwrap()
        .with_timezone(&Utc)
        + Duration::seconds(second)
}
fn event(second: i64, kind: EventType, source: &str, host: &str, user: &str) -> SecurityEvent {
    let mut e = SecurityEvent::new(kind, time(second), source, host);
    e.username = Some(user.into());
    e.service = Some("auth".into());
    e.result = Some(
        if matches!(kind, EventType::FailedLogin | EventType::MfaFailure) {
            "failure"
        } else {
            "success"
        }
        .into(),
    );
    e
}
fn failures(source: &str, user: &str, hosts: &[&str], spacing: i64) -> Vec<SecurityEvent> {
    hosts
        .iter()
        .enumerate()
        .map(|(i, host)| {
            event(
                i as i64 * spacing,
                EventType::FailedLogin,
                source,
                host,
                user,
            )
        })
        .collect()
}
fn familiar_history(source: &str, user: &str) -> Vec<SecurityEvent> {
    ["app-a", "app-b", "app-c"]
        .into_iter()
        .enumerate()
        .map(|(i, host)| {
            event(
                -86_400 * (i as i64 + 1),
                EventType::SuccessfulLogin,
                source,
                host,
                user,
            )
        })
        .collect()
}
fn noise() -> Vec<SecurityEvent> {
    (0..20)
        .map(|i| {
            event(
                i * 11,
                EventType::WebRequest,
                &format!("visitor-{}", i % 5),
                "web",
                "",
            )
        })
        .collect()
}
fn case(name: &'static str, malicious: bool, events: Vec<SecurityEvent>) -> Case {
    let mut mixed = events;
    mixed.extend(noise());
    mixed.sort_by_key(|e| e.timestamp);
    Case {
        name,
        malicious,
        history: Vec::new(),
        events: mixed,
    }
}
fn cases() -> Vec<Case> {
    use EventType::*;
    let distributed = ["app-a", "app-a", "app-b", "app-b", "app-c"];
    let mut set = vec![
        case(
            "normal_shared_login",
            false,
            vec![event(3, SuccessfulLogin, "employee", "app-a", "demo")],
        ),
        case("normal_web_only", false, vec![]),
        case(
            "distributed_rapid",
            true,
            failures("attacker", "demo", &distributed, 7),
        ),
        case(
            "distributed_spaced",
            true,
            failures("attacker", "demo", &distributed, 70),
        ),
        case(
            "distributed_beyond_window",
            true,
            failures("attacker", "demo", &distributed, 720),
        ),
        case(
            "brute_force",
            true,
            failures("attacker", "demo", &["app-a"; 6], 5),
        ),
        case(
            "mixed_accounts_nat",
            false,
            (0..5)
                .map(|i| {
                    event(
                        i * 7,
                        FailedLogin,
                        "shared-nat",
                        distributed[i as usize],
                        &format!("user-{i}"),
                    )
                })
                .collect(),
        ),
        case(
            "rotating_source",
            true,
            (0..5)
                .map(|i| {
                    event(
                        i * 7,
                        FailedLogin,
                        &format!("rotating-{i}"),
                        distributed[i as usize],
                        "demo",
                    )
                })
                .collect(),
        ),
        case(
            "mfa_attack",
            true,
            (0..4)
                .map(|i| event(i * 8, MfaFailure, "attacker", "app-a", "demo"))
                .collect(),
        ),
        case(
            "mfa_user_errors",
            false,
            (0..3)
                .map(|i| event(i * 30, MfaFailure, "employee", "app-a", "demo"))
                .collect(),
        ),
        case(
            "ordered_chain",
            true,
            vec![
                event(0, FailedLogin, "attacker", "app-a", "demo"),
                event(7, FailedLogin, "attacker", "app-a", "demo"),
                event(20, SuccessfulLogin, "attacker", "app-a", "demo"),
                event(30, PrivilegeAction, "attacker", "app-a", "demo"),
                event(40, UnusualNetworkActivity, "attacker", "app-a", "demo"),
            ],
        ),
        case(
            "reordered_activity",
            false,
            vec![
                event(0, UnusualNetworkActivity, "employee", "app-a", "demo"),
                event(20, PrivilegeAction, "employee", "app-a", "demo"),
                event(35, SuccessfulLogin, "employee", "app-a", "demo"),
            ],
        ),
        case(
            "success_after_failures",
            true,
            vec![
                event(0, FailedLogin, "attacker", "app-a", "demo"),
                event(7, FailedLogin, "attacker", "app-a", "demo"),
                event(25, SuccessfulLogin, "attacker", "app-a", "demo"),
            ],
        ),
        case(
            "legitimate_password_typos",
            false,
            vec![
                event(0, FailedLogin, "employee", "app-a", "demo"),
                event(12, FailedLogin, "employee", "app-a", "demo"),
                event(40, SuccessfulLogin, "employee", "app-a", "demo"),
            ],
        ),
        case(
            "new_source_success",
            true,
            vec![event(5, SuccessfulLogin, "new-device", "app-c", "demo")],
        ),
        case(
            "legitimate_new_device",
            false,
            vec![event(5, SuccessfulLogin, "travel-device", "app-c", "demo")],
        ),
    ];
    for name in [
        "legitimate_password_typos",
        "legitimate_new_device",
        "mfa_user_errors",
    ] {
        set.iter_mut()
            .find(|case| case.name == name)
            .unwrap()
            .history = familiar_history("employee", "demo");
    }
    set.iter_mut()
        .find(|case| case.name == "new_source_success")
        .unwrap()
        .history = familiar_history("employee", "demo");
    set
}

/// Stateful centralized rules with the same source, account, host and time data.
/// It intentionally uses no graph representation or TACG score.
fn centralized_rules(events: &[SecurityEvent], history: &[SecurityEvent]) -> bool {
    use EventType::*;
    let mut by_identity: HashMap<(&str, &str), Vec<&SecurityEvent>> = HashMap::new();
    for e in events {
        if let (Some(source), Some(user)) = (e.source_ip.as_deref(), e.username.as_deref()) {
            by_identity.entry((source, user)).or_default().push(e);
        }
    }
    for ((source, user), mut group) in by_identity {
        group.sort_by_key(|e| e.timestamp);
        let failures: Vec<_> = group
            .iter()
            .copied()
            .filter(|e| e.event_type == FailedLogin)
            .collect();
        let mfa: Vec<_> = group
            .iter()
            .copied()
            .filter(|e| e.event_type == MfaFailure)
            .collect();
        let prior: Vec<_> = history
            .iter()
            .filter(|e| e.event_type == SuccessfulLogin && e.username.as_deref() == Some(user))
            .collect();
        for (i, anchor) in failures.iter().enumerate() {
            let window: Vec<_> = failures[i..]
                .iter()
                .copied()
                .filter(|e| e.timestamp - anchor.timestamp <= Duration::seconds(600))
                .collect();
            let hosts: HashSet<_> = window
                .iter()
                .filter_map(|e| e.hostname.as_deref())
                .collect();
            let familiar = prior.len() >= 3
                && prior.iter().any(|e| e.source_ip.as_deref() == Some(source))
                && hosts
                    .iter()
                    .all(|host| prior.iter().any(|e| e.hostname.as_deref() == Some(host)));
            if window.len() >= 5 && hosts.len() >= 3 && !familiar {
                return true;
            }
            if window
                .iter()
                .filter(|e| e.hostname == anchor.hostname)
                .count()
                >= 6
            {
                return true;
            }
        }
        for (i, anchor) in mfa.iter().enumerate() {
            if mfa[i..]
                .iter()
                .filter(|e| e.timestamp - anchor.timestamp <= Duration::seconds(300))
                .count()
                >= 3
            {
                return true;
            }
        }
        for login in group.iter().filter(|e| e.event_type == SuccessfulLogin) {
            let preceding = failures
                .iter()
                .filter(|e| {
                    e.timestamp < login.timestamp
                        && login.timestamp - e.timestamp <= Duration::seconds(600)
                })
                .count();
            if preceding >= 2 {
                return true;
            }
            if prior.len() >= 3 && !prior.iter().any(|e| e.source_ip.as_deref() == Some(source)) {
                return true;
            }
        }
        if group.iter().any(|e| e.event_type == UnauthorizedAccess) {
            return true;
        }
        // Chronological state machine; every stage must follow its predecessor.
        let mut stage = 0;
        let mut first = None;
        for e in &group {
            if stage > 0 && first.is_some_and(|at| e.timestamp - at > Duration::seconds(600)) {
                stage = 0;
                first = None;
            }
            match (stage, e.event_type) {
                (0, FailedLogin) => {
                    stage = 1;
                    first = Some(e.timestamp);
                }
                (1, SuccessfulLogin) => stage = 2,
                (2, PrivilegeAction) => stage = 3,
                (3, UnusualNetworkActivity) => return true,
                _ => {}
            }
        }
    }
    false
}
fn tacg_alert(events: &[SecurityEvent], history: &[SecurityEvent]) -> (bool, bool) {
    let mut all = history.to_vec();
    all.extend_from_slice(events);
    let baseline = Baseline::learn(&all);
    let current: HashSet<_> = events.iter().map(|e| e.id).collect();
    let incidents = correlate(&all, &baseline);
    let matching: Vec<_> = incidents
        .iter()
        .filter(|i| i.events.iter().any(|e| current.contains(&e.id)))
        .collect();
    (
        matching.iter().any(|i| i.risk >= 40),
        matching.iter().any(|i| i.risk >= 85),
    )
}
#[test]
fn mixed_traffic_comparison_against_stateful_rules() {
    let cases = cases();
    let mut tacg = Metrics::default();
    let mut rules = Metrics::default();
    for case in &cases {
        let (tacg_final, critical) = tacg_alert(&case.events, &case.history);
        let rules_final = centralized_rules(&case.events, &case.history);
        let mut tacg_delay = None;
        let mut rules_delay = None;
        for end in 1..=case.events.len() {
            let prefix = &case.events[..end];
            let delay = (prefix.last().unwrap().timestamp - case.events[0].timestamp).num_seconds();
            if tacg_delay.is_none() && tacg_alert(prefix, &case.history).0 {
                tacg_delay = Some(delay);
            }
            if rules_delay.is_none() && centralized_rules(prefix, &case.history) {
                rules_delay = Some(delay);
            }
        }
        tacg.record(
            case.malicious,
            tacg_final,
            critical,
            case.malicious.then_some(tacg_delay).flatten(),
        );
        rules.record(
            case.malicious,
            rules_final,
            false,
            case.malicious.then_some(rules_delay).flatten(),
        );
        println!(
            "{} label={} TACG={} risk>=85={} rules={} TACG-delay={:?} rules-delay={:?}",
            case.name, case.malicious, tacg_final, critical, rules_final, tacg_delay, rules_delay
        );
    }
    assert_eq!(cases.len(), 16);
    // Explicit regression assertions protecting detection quality, precision, recall, and safety
    assert_eq!(
        tacg.benign_critical, 0,
        "TACG must never produce critical false positives on benign cases"
    );
    assert_eq!(
        tacg.fp, 0,
        "TACG must maintain zero false positives on authored test fixtures"
    );
    assert!(
        tacg.tp >= 7,
        "TACG must catch at least 7 of 9 attacks (TP >= 7)"
    );
    assert_eq!(
        tacg.tn, 7,
        "TACG must correctly identify all 7 benign scenarios (TN == 7)"
    );
    let tacg_precision = tacg.tp as f64 / (tacg.tp + tacg.fp) as f64;
    let tacg_recall = tacg.tp as f64 / (tacg.tp + tacg.fn_) as f64;
    let tacg_fpr = tacg.fp as f64 / (tacg.fp + tacg.tn) as f64;
    assert!(
        tacg_precision >= 0.95,
        "TACG precision must be >= 0.95, got {tacg_precision}"
    );
    assert!(
        tacg_recall >= 0.75,
        "TACG recall must be >= 0.75, got {tacg_recall}"
    );
    assert!(tacg_fpr <= 0.05, "TACG FPR must be <= 0.05, got {tacg_fpr}");

    let rules_precision = rules.tp as f64 / (rules.tp + rules.fp) as f64;
    let rules_fpr = rules.fp as f64 / (rules.fp + rules.tn) as f64;
    assert!(
        tacg_precision > rules_precision,
        "TACG precision ({tacg_precision:.2}) must exceed centralized rules ({rules_precision:.2})"
    );
    assert!(
        tacg_fpr < rules_fpr,
        "TACG FPR ({tacg_fpr:.2}) must be strictly lower than centralized rules ({rules_fpr:.2})"
    );

    println!("TACG: {}", tacg.summary());
    println!("centralized rules: {}", rules.summary());
}
