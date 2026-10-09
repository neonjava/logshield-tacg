use logshield_core::{baseline::Baseline, demo::scenario, event::EventType, tacg::correlate};
use std::collections::HashMap;

#[test]
fn small_labeled_comparison_against_simple_counters() {
    let distributed = scenario("distributed");
    let mut mixed_accounts = distributed.clone();
    for (index, event) in mixed_accounts.iter_mut().enumerate() {
        event.username = Some(format!("account-{index}"));
    }
    let mut prior_success = [0, 2, 4].map(|index| distributed[index].clone());
    for (index, event) in prior_success.iter_mut().enumerate() {
        event.event_type = EventType::SuccessfulLogin;
        event.timestamp -= chrono::Duration::minutes(index as i64 + 20);
    }
    let cases = [
        (
            "distributed",
            distributed.clone(),
            Baseline::default(),
            true,
        ),
        (
            "ordered_chain",
            scenario("multistage"),
            Baseline::default(),
            true,
        ),
        ("mixed_accounts", mixed_accounts, Baseline::default(), false),
        (
            "familiar_account",
            distributed,
            Baseline::learn(&prior_success),
            false,
        ),
        ("normal", scenario("normal"), Baseline::default(), false),
    ];
    let mut tacg = (0, 0, 0);
    let mut central = (0, 0, 0);
    let mut per_host = (0, 0, 0);
    for (name, events, baseline, attack) in cases {
        let detected = correlate(&events, &baseline).iter().any(|i| i.risk >= 85);
        let failures = events
            .iter()
            .filter(|e| e.event_type == EventType::FailedLogin)
            .count();
        let mut hosts = HashMap::new();
        for event in events
            .iter()
            .filter(|e| e.event_type == EventType::FailedLogin)
        {
            *hosts.entry(event.hostname.as_deref()).or_insert(0) += 1;
        }
        for (result, positive) in [
            (&mut tacg, detected),
            (&mut central, failures >= 5),
            (&mut per_host, hosts.values().any(|count| *count >= 5)),
        ] {
            if positive && attack {
                result.0 += 1;
            }
            if positive && !attack {
                result.1 += 1;
            }
            if !positive && attack {
                result.2 += 1;
            }
        }
        println!(
            "{name}: attack={attack} tacg={detected} central={} per_host={}",
            failures >= 5,
            hosts.values().any(|count| *count >= 5)
        );
    }
    // (true positives, false positives, false negatives) on five hand-built fixtures.
    assert_eq!(tacg, (2, 0, 0));
    assert_eq!(central, (1, 2, 1));
    assert_eq!(per_host, (0, 0, 2));
}
