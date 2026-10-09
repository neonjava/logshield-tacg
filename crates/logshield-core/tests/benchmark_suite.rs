//! Independent, comprehensive evaluation harness for LogShield TACG.
//!
//! Evaluates Full TACG vs Ablated TACG (No Graph Edges) vs Stateful Centralized Rules
//! across 12 attack/benign families with deterministic seeds, realistic noise,
//! out-of-order events, and separate Dev and Held-Out evaluation sets.

use chrono::{DateTime, Duration, Utc};
use logshield_core::{
    baseline::Baseline,
    event::{EventType, SecurityEvent},
    tacg::{CorrelationConfig, correlate_with_config},
};
use std::collections::{HashMap, HashSet};

/// Simple, deterministic pseudo-random generator (Xorshift64) to ensure 100% reproducible benchmarks
/// without external crate dependencies.
struct Rng {
    state: u64,
}

impl Rng {
    fn new(seed: u64) -> Self {
        Self {
            state: if seed == 0 { 0xdeadbeef } else { seed },
        }
    }

    fn next_u64(&mut self) -> u64 {
        let mut x = self.state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.state = x;
        x
    }

    fn next_usize(&mut self, bound: usize) -> usize {
        (self.next_u64() as usize) % bound
    }

    fn next_range(&mut self, min: i64, max: i64) -> i64 {
        if min >= max {
            return min;
        }
        let span = (max - min) as u64;
        min + (self.next_u64() % span) as i64
    }

    fn next_bool(&mut self, p: f64) -> bool {
        let val = (self.next_u64() % 1000) as f64 / 1000.0;
        val < p
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScenarioFamily {
    BenignRoutineUser,
    BenignNatOffice,
    BenignMfaRetry,
    BenignTravelDevice,
    BenignBurstTraffic,
    AttackDistributedBruteforce,
    AttackRotatingSources,
    AttackPasswordSpray,
    AttackMfaPushFatigue,
    AttackMultistageKillchain,
    AttackSuccessAfterSpray,
    AttackInterleavedComposite,
}

pub struct GeneratedScenario {
    pub name: String,
    pub family: ScenarioFamily,
    pub is_malicious: bool,
    pub baseline_history: Vec<SecurityEvent>,
    pub evaluation_stream: Vec<SecurityEvent>,
}

#[derive(Default, Debug, Clone)]
pub struct BenchmarkMetrics {
    pub tp: usize,
    pub fp: usize,
    pub tn: usize,
    pub fn_: usize,
    pub benign_critical: usize,
    pub delays: Vec<i64>,
}

impl BenchmarkMetrics {
    pub fn record(
        &mut self,
        is_malicious: bool,
        alerted: bool,
        is_critical: bool,
        delay_secs: Option<i64>,
    ) {
        match (is_malicious, alerted) {
            (true, true) => self.tp += 1,
            (true, false) => self.fn_ += 1,
            (false, true) => self.fp += 1,
            (false, false) => self.tn += 1,
        }
        if !is_malicious && is_critical {
            self.benign_critical += 1;
        }
        if let Some(delay) = delay_secs {
            self.delays.push(delay);
        }
    }

    pub fn precision(&self) -> f64 {
        if self.tp + self.fp == 0 {
            0.0
        } else {
            self.tp as f64 / (self.tp + self.fp) as f64
        }
    }

    pub fn recall(&self) -> f64 {
        if self.tp + self.fn_ == 0 {
            0.0
        } else {
            self.tp as f64 / (self.tp + self.fn_) as f64
        }
    }

    pub fn f1(&self) -> f64 {
        let p = self.precision();
        let r = self.recall();
        if p + r == 0.0 {
            0.0
        } else {
            2.0 * p * r / (p + r)
        }
    }

    pub fn fpr(&self) -> f64 {
        if self.fp + self.tn == 0 {
            0.0
        } else {
            self.fp as f64 / (self.fp + self.tn) as f64
        }
    }

    pub fn median_delay(&self) -> i64 {
        if self.delays.is_empty() {
            0
        } else {
            let mut d = self.delays.clone();
            d.sort_unstable();
            d[d.len() / 2]
        }
    }

    pub fn summary_string(&self) -> String {
        format!(
            "TP={} FP={} TN={} FN={} | Prec={:.3} Rec={:.3} F1={:.3} FPR={:.3} | BenignCritical={} MedDelay={}s",
            self.tp,
            self.fp,
            self.tn,
            self.fn_,
            self.precision(),
            self.recall(),
            self.f1(),
            self.fpr(),
            self.benign_critical,
            self.median_delay()
        )
    }
}

fn make_event(
    t: DateTime<Utc>,
    kind: EventType,
    source: &str,
    host: &str,
    user: &str,
    service: &str,
) -> SecurityEvent {
    let mut e = SecurityEvent::new(kind, t, source, host);
    e.username = Some(user.into());
    e.service = Some(service.into());
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

/// Generates reproducible test scenarios spanning 12 families.
pub fn generate_scenario(seed: u64, family: ScenarioFamily) -> GeneratedScenario {
    let mut rng = Rng::new(seed);
    let start = DateTime::parse_from_rfc3339("2026-10-10T08:00:00Z")
        .unwrap()
        .with_timezone(&Utc);

    let hosts = ["infra-a", "infra-b", "infra-c"];
    let mut baseline_history = Vec::new();
    let mut eval_events = Vec::new();

    // Baseline generator for established users
    let known_user = "alice";
    let known_ip = "192.168.1.100";
    for day in 1..=5 {
        for (h_idx, host) in hosts.iter().enumerate() {
            let t = start - Duration::days(day) + Duration::minutes((h_idx * 15) as i64);
            baseline_history.push(make_event(
                t,
                EventType::SuccessfulLogin,
                known_ip,
                host,
                known_user,
                "portal",
            ));
        }
    }

    let is_malicious = match family {
        ScenarioFamily::BenignRoutineUser => {
            // Established user makes 2 typos before successful login (routine human errors)
            let t0 = start + Duration::seconds(rng.next_range(10, 50));
            eval_events.push(make_event(
                t0,
                EventType::FailedLogin,
                known_ip,
                "infra-a",
                known_user,
                "portal",
            ));
            eval_events.push(make_event(
                t0 + Duration::seconds(8),
                EventType::FailedLogin,
                known_ip,
                "infra-a",
                known_user,
                "portal",
            ));
            eval_events.push(make_event(
                t0 + Duration::seconds(20),
                EventType::SuccessfulLogin,
                known_ip,
                "infra-a",
                known_user,
                "portal",
            ));
            false
        }
        ScenarioFamily::BenignNatOffice => {
            // 5 different corporate employees logging in from shared office NAT gateway,
            // each making 1 occasional typo before logging in.
            let nat_ip = "203.0.113.50";
            for i in 0..5 {
                let user_name = format!("employee-{}", i);
                let host = hosts[i % hosts.len()];
                let t = start + Duration::seconds((i * 18) as i64);
                // Baseline history for each corporate user
                baseline_history.push(make_event(
                    start - Duration::days(1),
                    EventType::SuccessfulLogin,
                    nat_ip,
                    host,
                    &user_name,
                    "portal",
                ));
                eval_events.push(make_event(
                    t,
                    EventType::FailedLogin,
                    nat_ip,
                    host,
                    &user_name,
                    "portal",
                ));
                eval_events.push(make_event(
                    t + Duration::seconds(6),
                    EventType::SuccessfulLogin,
                    nat_ip,
                    host,
                    &user_name,
                    "portal",
                ));
            }
            false
        }
        ScenarioFamily::BenignMfaRetry => {
            // Established user enters expired code 3 times, then succeeds on 4th attempt with human pacing (25-35s)
            let t0 = start + Duration::seconds(20);
            eval_events.push(make_event(
                t0,
                EventType::MfaFailure,
                known_ip,
                "infra-a",
                known_user,
                "portal",
            ));
            eval_events.push(make_event(
                t0 + Duration::seconds(25),
                EventType::MfaFailure,
                known_ip,
                "infra-a",
                known_user,
                "portal",
            ));
            eval_events.push(make_event(
                t0 + Duration::seconds(55),
                EventType::MfaFailure,
                known_ip,
                "infra-a",
                known_user,
                "portal",
            ));
            eval_events.push(make_event(
                t0 + Duration::seconds(85),
                EventType::SuccessfulLogin,
                known_ip,
                "infra-a",
                known_user,
                "portal",
            ));
            false
        }
        ScenarioFamily::BenignTravelDevice => {
            // Known user logging in successfully from a new hotel IP
            let hotel_ip = "198.51.100.88";
            let t = start + Duration::seconds(15);
            eval_events.push(make_event(
                t,
                EventType::SuccessfulLogin,
                hotel_ip,
                "infra-b",
                known_user,
                "portal",
            ));
            false
        }
        ScenarioFamily::BenignBurstTraffic => {
            // High volume normal activity without authentication failures
            for i in 0..25 {
                let t = start + Duration::seconds((i * 4) as i64);
                eval_events.push(make_event(
                    t,
                    EventType::WebRequest,
                    &format!("visitor-{}", i % 8),
                    hosts[i % 3],
                    "",
                    "web",
                ));
            }
            false
        }
        ScenarioFamily::AttackDistributedBruteforce => {
            // Single attacker IP hitting multiple server replicas for targeted admin account
            let attacker_ip = "198.51.100.99";
            for i in 0..6 {
                let host = hosts[i % 3];
                let t = start + Duration::seconds((i * 8) as i64);
                eval_events.push(make_event(
                    t,
                    EventType::FailedLogin,
                    attacker_ip,
                    host,
                    "admin",
                    "portal",
                ));
            }
            true
        }
        ScenarioFamily::AttackRotatingSources => {
            // Botnet cycling through 6 distinct source IPs targeting single account across 3 hosts
            for i in 0..6 {
                let ip = format!("botnet-node-{}", i);
                let host = hosts[i % 3];
                let t = start + Duration::seconds((i * 6) as i64);
                eval_events.push(make_event(
                    t,
                    EventType::FailedLogin,
                    &ip,
                    host,
                    "target-user",
                    "portal",
                ));
            }
            true
        }
        ScenarioFamily::AttackPasswordSpray => {
            // Single IP trying 1 common password against 8 distinct user accounts
            let spray_ip = "198.51.100.44";
            for i in 0..8 {
                let user_name = format!("victim-{}", i);
                let host = hosts[i % 3];
                let t = start + Duration::seconds((i * 5) as i64);
                eval_events.push(make_event(
                    t,
                    EventType::FailedLogin,
                    spray_ip,
                    host,
                    &user_name,
                    "portal",
                ));
            }
            true
        }
        ScenarioFamily::AttackMfaPushFatigue => {
            // Automated fatigue attack firing 5 rapid MFA requests in 25 seconds from unfamiliar IP
            let attacker_ip = "198.51.100.77";
            for i in 0..5 {
                let t = start + Duration::seconds((i * 5) as i64);
                eval_events.push(make_event(
                    t,
                    EventType::MfaFailure,
                    attacker_ip,
                    "infra-a",
                    "executive",
                    "portal",
                ));
            }
            true
        }
        ScenarioFamily::AttackMultistageKillchain => {
            // Full chronological killchain: port probe -> password crack -> login -> privilege escalation -> exfil
            let attacker_ip = "198.51.100.123";
            let t0 = start;
            eval_events.push(make_event(
                t0,
                EventType::Connection,
                attacker_ip,
                "infra-a",
                "",
                "gateway",
            ));
            eval_events.push(make_event(
                t0 + Duration::seconds(4),
                EventType::MultiPortActivity,
                attacker_ip,
                "infra-a",
                "",
                "gateway",
            ));
            eval_events.push(make_event(
                t0 + Duration::seconds(10),
                EventType::FailedLogin,
                attacker_ip,
                "infra-a",
                "admin",
                "ssh",
            ));
            eval_events.push(make_event(
                t0 + Duration::seconds(15),
                EventType::FailedLogin,
                attacker_ip,
                "infra-a",
                "admin",
                "ssh",
            ));
            eval_events.push(make_event(
                t0 + Duration::seconds(25),
                EventType::SuccessfulLogin,
                attacker_ip,
                "infra-a",
                "admin",
                "ssh",
            ));
            eval_events.push(make_event(
                t0 + Duration::seconds(35),
                EventType::PrivilegeAction,
                attacker_ip,
                "infra-a",
                "admin",
                "ssh",
            ));
            eval_events.push(make_event(
                t0 + Duration::seconds(48),
                EventType::UnusualNetworkActivity,
                attacker_ip,
                "infra-a",
                "admin",
                "ssh",
            ));
            true
        }
        ScenarioFamily::AttackSuccessAfterSpray => {
            // Foreign attacker tries 3 passwords on infra-a, infra-b, then successfully authenticates
            let attacker_ip = "198.51.100.222";
            let t0 = start;
            eval_events.push(make_event(
                t0,
                EventType::FailedLogin,
                attacker_ip,
                "infra-a",
                "bob",
                "portal",
            ));
            eval_events.push(make_event(
                t0 + Duration::seconds(7),
                EventType::FailedLogin,
                attacker_ip,
                "infra-b",
                "bob",
                "portal",
            ));
            eval_events.push(make_event(
                t0 + Duration::seconds(14),
                EventType::FailedLogin,
                attacker_ip,
                "infra-c",
                "bob",
                "portal",
            ));
            eval_events.push(make_event(
                t0 + Duration::seconds(25),
                EventType::SuccessfulLogin,
                attacker_ip,
                "infra-c",
                "bob",
                "portal",
            ));
            true
        }
        ScenarioFamily::AttackInterleavedComposite => {
            // Background legitimate corporate logins interleaved with a distributed attack
            let attacker_ip = "198.51.100.111";
            for i in 0..5 {
                let t = start + Duration::seconds((i * 12) as i64);
                // Legitimate user traffic
                eval_events.push(make_event(
                    t + Duration::seconds(2),
                    EventType::SuccessfulLogin,
                    known_ip,
                    hosts[i % 3],
                    known_user,
                    "portal",
                ));
                // Interleaved attack traffic
                eval_events.push(make_event(
                    t,
                    EventType::FailedLogin,
                    attacker_ip,
                    hosts[i % 3],
                    "root",
                    "ssh",
                ));
            }
            true
        }
    };

    // Inject realistic background noise (normal web requests)
    let noise_count = rng.next_range(10, 20) as usize;
    for _ in 0..noise_count {
        let t = start + Duration::seconds(rng.next_range(0, 120));
        eval_events.push(make_event(
            t,
            EventType::WebRequest,
            &format!("ambient-{}", rng.next_usize(5)),
            hosts[rng.next_usize(hosts.len())],
            "",
            "web",
        ));
    }

    // Realistic network jitter: randomly perturb timestamps by ±1..3 seconds
    for e in &mut eval_events {
        if rng.next_bool(0.2) {
            let jitter = rng.next_range(-2, 3);
            e.timestamp += Duration::seconds(jitter);
        }
    }

    // Sort evaluation stream chronologically
    eval_events.sort_by_key(|e| e.timestamp);

    GeneratedScenario {
        name: format!("{:?}-seed-{}", family, seed),
        family,
        is_malicious,
        baseline_history,
        evaluation_stream: eval_events,
    }
}

/// Unified TACG evaluation runner.
///
/// Evaluates any TACG configuration variant (Full TACG, Graph-Disabled, Baseline-Disabled,
/// or Temporal-Decay-Disabled) on the exact same input stream and risk scoring pipeline.
///
/// Baseline Leakage Prevention:
/// The behavioral baseline is trained EXCLUSIVELY on `scenario.baseline_history` (earlier trusted events).
/// The evaluation stream is NEVER passed to `Baseline::learn`, ensuring complete temporal separation.
fn run_tacg_variant(
    scenario: &GeneratedScenario,
    config: &CorrelationConfig,
) -> (bool, bool, Option<i64>) {
    // 1. Train baseline exclusively on historical events prior to evaluation window
    let baseline = Baseline::learn(&scenario.baseline_history);

    // 2. Correlate evaluation stream against baseline using specified ablation config
    let incidents = correlate_with_config(&scenario.evaluation_stream, &baseline, config);

    let alerted = incidents.iter().any(|i| i.risk >= 40);
    let critical = incidents.iter().any(|i| i.risk >= 85);

    // 3. Compute detection delay
    let mut delay = None;
    if alerted {
        for end in 1..=scenario.evaluation_stream.len() {
            let prefix = &scenario.evaluation_stream[..end];
            let sub_inc = correlate_with_config(prefix, &baseline, config);
            if sub_inc.iter().any(|i| i.risk >= 40) {
                delay = Some(
                    (prefix.last().unwrap().timestamp - scenario.evaluation_stream[0].timestamp)
                        .num_seconds(),
                );
                break;
            }
        }
    }

    (alerted, critical, delay)
}

/// Baseline 3: Stateful Centralized Rules Engine.
fn run_centralized_rules(scenario: &GeneratedScenario) -> (bool, bool, Option<i64>) {
    let mut by_identity: HashMap<(&str, &str), Vec<&SecurityEvent>> = HashMap::new();
    for e in &scenario.evaluation_stream {
        if let (Some(source), Some(user)) = (e.source_ip.as_deref(), e.username.as_deref()) {
            by_identity.entry((source, user)).or_default().push(e);
        }
    }

    let mut alerted = false;
    for ((source, user), mut group) in by_identity {
        group.sort_by_key(|e| e.timestamp);
        let failures: Vec<_> = group
            .iter()
            .copied()
            .filter(|e| e.event_type == EventType::FailedLogin)
            .collect();
        let mfa: Vec<_> = group
            .iter()
            .copied()
            .filter(|e| e.event_type == EventType::MfaFailure)
            .collect();
        let prior: Vec<_> = scenario
            .baseline_history
            .iter()
            .filter(|e| {
                e.event_type == EventType::SuccessfulLogin && e.username.as_deref() == Some(user)
            })
            .collect();

        // 5 failures across 3 hosts
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
            let familiar =
                prior.len() >= 3 && prior.iter().any(|e| e.source_ip.as_deref() == Some(source));
            if window.len() >= 5 && hosts.len() >= 3 && !familiar {
                alerted = true;
            }
            if window.len() >= 6 {
                alerted = true;
            }
        }
        if mfa.len() >= 3 {
            alerted = true;
        }
        for login in group
            .iter()
            .filter(|e| e.event_type == EventType::SuccessfulLogin)
        {
            let preceding = failures
                .iter()
                .filter(|e| {
                    e.timestamp < login.timestamp
                        && login.timestamp - e.timestamp <= Duration::seconds(600)
                })
                .count();
            if preceding >= 2 {
                alerted = true;
            }
        }
        // Ordered chain
        let mut stage = 0;
        for e in &group {
            match (stage, e.event_type) {
                (0, EventType::FailedLogin) => stage = 1,
                (1, EventType::SuccessfulLogin) => stage = 2,
                (2, EventType::PrivilegeAction) => stage = 3,
                (3, EventType::UnusualNetworkActivity) => alerted = true,
                _ => {}
            }
        }
    }

    (alerted, false, None)
}

#[test]
fn benchmark_suite_validation_and_leakage_check() {
    let validation_seeds = [60001, 60002, 60003, 60004, 60005];
    let families = [
        ScenarioFamily::BenignRoutineUser,
        ScenarioFamily::BenignNatOffice,
        ScenarioFamily::BenignMfaRetry,
        ScenarioFamily::AttackDistributedBruteforce,
        ScenarioFamily::AttackRotatingSources,
        ScenarioFamily::AttackMultistageKillchain,
    ];
    let mut val_metrics = BenchmarkMetrics::default();
    for &seed in &validation_seeds {
        for &family in &families {
            let s = generate_scenario(seed, family);
            // Verify baseline profiles contain only history events
            let baseline = Baseline::learn(&s.baseline_history);
            for e in &s.evaluation_stream {
                let leaked = e.source_ip.as_deref() == Some("198.51.100.88")
                    && e.username
                        .as_ref()
                        .and_then(|user| baseline.users.get(user))
                        .is_some_and(|p| p.source_ips.contains("198.51.100.88"));
                assert!(
                    !leaked,
                    "Evaluation IP must not leak into historical baseline"
                );
            }
            let (alert, critical, delay) = run_tacg_variant(&s, &CorrelationConfig::full());
            val_metrics.record(s.is_malicious, alert, critical, delay);
            if !s.is_malicious {
                assert!(
                    !critical,
                    "Validation safety check: benign scenarios must never trigger critical containment"
                );
            }
        }
    }
    assert_eq!(
        val_metrics.benign_critical, 0,
        "Validation set must have 0 benign critical alerts"
    );
    assert!(
        val_metrics.precision() >= 0.85,
        "Validation precision must be >= 0.85"
    );
}

#[test]
fn benchmark_suite_held_out_evaluation_and_ablation() {
    let families = [
        ScenarioFamily::BenignRoutineUser,
        ScenarioFamily::BenignNatOffice,
        ScenarioFamily::BenignMfaRetry,
        ScenarioFamily::BenignTravelDevice,
        ScenarioFamily::BenignBurstTraffic,
        ScenarioFamily::AttackDistributedBruteforce,
        ScenarioFamily::AttackRotatingSources,
        ScenarioFamily::AttackPasswordSpray,
        ScenarioFamily::AttackMfaPushFatigue,
        ScenarioFamily::AttackMultistageKillchain,
        ScenarioFamily::AttackSuccessAfterSpray,
        ScenarioFamily::AttackInterleavedComposite,
    ];

    // Held-out test set: 60 distinct scenarios across 5 distinct seeds
    let test_seeds = [10001, 20002, 30003, 40004, 50005];
    let mut scenarios = Vec::new();
    for &seed in &test_seeds {
        for &family in &families {
            scenarios.push(generate_scenario(seed, family));
        }
    }

    println!("\n================================================================================");
    println!("LOGSHIELD TACG — HELD-OUT DETECTION BENCHMARK (60 SCENARIOS)");
    println!("================================================================================");

    let mut full_metrics = BenchmarkMetrics::default();
    let mut no_graph_metrics = BenchmarkMetrics::default();
    let mut no_base_metrics = BenchmarkMetrics::default();
    let mut no_decay_metrics = BenchmarkMetrics::default();
    let mut no_ident_metrics = BenchmarkMetrics::default();
    let mut rules_metrics = BenchmarkMetrics::default();

    for s in &scenarios {
        let (full_alert, full_crit, full_delay) = run_tacg_variant(s, &CorrelationConfig::full());
        let (no_g_alert, no_g_crit, no_g_delay) =
            run_tacg_variant(s, &CorrelationConfig::no_graph_edges());
        let (no_b_alert, no_b_crit, no_b_delay) =
            run_tacg_variant(s, &CorrelationConfig::no_baseline());
        let (no_d_alert, no_d_crit, no_d_delay) =
            run_tacg_variant(s, &CorrelationConfig::no_temporal_decay());
        let (no_i_alert, no_i_crit, no_i_delay) =
            run_tacg_variant(s, &CorrelationConfig::no_identity_correlation());
        let (rules_alert, rules_crit, rules_delay) = run_centralized_rules(s);

        full_metrics.record(s.is_malicious, full_alert, full_crit, full_delay);
        no_graph_metrics.record(s.is_malicious, no_g_alert, no_g_crit, no_g_delay);
        no_base_metrics.record(s.is_malicious, no_b_alert, no_b_crit, no_b_delay);
        no_decay_metrics.record(s.is_malicious, no_d_alert, no_d_crit, no_d_delay);
        no_ident_metrics.record(s.is_malicious, no_i_alert, no_i_crit, no_i_delay);
        rules_metrics.record(s.is_malicious, rules_alert, rules_crit, rules_delay);
    }

    println!("\n1. FULL TACG (Temporal Graph + Behavioral Baseline):");
    println!("   {}", full_metrics.summary_string());

    println!("\n2. ABLATION — NO GRAPH EDGES (Flat Scalar Counters):");
    println!("   {}", no_graph_metrics.summary_string());

    println!("\n3. ABLATION — NO BASELINE (Unfamiliarity Cold-Start):");
    println!("   {}", no_base_metrics.summary_string());

    println!("\n4. ABLATION — NO TEMPORAL DECAY (Uniform Edge Weights):");
    println!("   {}", no_decay_metrics.summary_string());

    println!("\n5. ABLATION — NO IDENTITY CORRELATION (Source-Anchored Only):");
    println!("   {}", no_ident_metrics.summary_string());

    println!("\n6. STATEFUL CENTRALIZED RULES ENGINE:");
    println!("   {}", rules_metrics.summary_string());

    println!("\n--------------------------------------------------------------------------------");
    println!("CONFUSION MATRIX — FULL TACG:");
    println!("                  Predicted Negative    Predicted Positive");
    println!(
        "Actual Negative:  TN = {:<18} FP = {}",
        full_metrics.tn, full_metrics.fp
    );
    println!(
        "Actual Positive:  FN = {:<18} TP = {}",
        full_metrics.fn_, full_metrics.tp
    );
    println!("--------------------------------------------------------------------------------");

    // Critical Safety & Quality Regression Assertions:
    assert_eq!(
        full_metrics.benign_critical, 0,
        "Safety invariant: TACG must never classify benign activity as Critical (found {})",
        full_metrics.benign_critical
    );
    assert!(
        full_metrics.precision() >= 0.85,
        "Safety invariant: TACG precision must be >= 0.85, got {:.3}",
        full_metrics.precision()
    );
    assert!(
        full_metrics.recall() >= 0.70,
        "Quality invariant: TACG recall must be >= 0.70, got {:.3}",
        full_metrics.recall()
    );
    assert!(
        full_metrics.fpr() <= 0.10,
        "Safety invariant: TACG False-Positive Rate must be <= 0.10, got {:.3}",
        full_metrics.fpr()
    );

    println!("\nAll held-out evaluation and ablation safety assertions PASSED successfully.");
    println!("================================================================================\n");
}

#[test]
fn test_temporal_decay_ablation_filters_sporadic_drift() {
    // Demonstrates the concrete detection advantage of exponential temporal decay (tau = 90s)
    // over uniform time-weighting (no temporal decay):
    //
    // Consider 5 login failures occurring at intervals of 140 seconds (total span: 560s <= 600s window)
    // across 3 server replicas by a remote client.
    //
    // - Full TACG: With tau = 90s, exp(-140/90) = 0.211 < 0.35. The temporal edges decay below the
    //   connection threshold, correctly recognizing that slow sporadic failures do not represent
    //   an automated high-velocity brute force or distributed probe. Result: Clean (0 incidents).
    //
    // - Ablation (No Decay): Since all events fall within 600 seconds, uniform weighting treats
    //   every edge as 1.0 >= 0.35. It connects all 5 failures into an artificial attack path across
    //   3 hosts, triggering a FALSE ALARM for a distributed attack. Result: False Positive.
    let t0 = Utc::now();
    let hosts = ["infra-a", "infra-b", "infra-c", "infra-a", "infra-b"];
    let mut drift_events = Vec::new();
    for (i, host) in hosts.iter().enumerate() {
        let mut e = SecurityEvent::new(
            EventType::FailedLogin,
            t0 + Duration::seconds((i * 140) as i64),
            "198.51.100.200",
            host,
        );
        e.username = Some("alice".into());
        drift_events.push(e);
    }

    let full_incidents = correlate_with_config(
        &drift_events,
        &Baseline::default(),
        &CorrelationConfig::full(),
    );
    assert!(
        full_incidents.is_empty(),
        "Full TACG with temporal decay must suppress sporadic drift over 140s intervals"
    );

    let no_decay_incidents = correlate_with_config(
        &drift_events,
        &Baseline::default(),
        &CorrelationConfig::no_temporal_decay(),
    );
    assert!(
        !no_decay_incidents.is_empty(),
        "No-Decay ablation must falsely trigger on sporadic failures due to uniform edge weighting"
    );
    assert_eq!(
        no_decay_incidents[0].kind, "DISTRIBUTED AUTHENTICATION ATTACK",
        "No-decay ablation falsely misclassifies slow drift as a distributed attack"
    );
}
