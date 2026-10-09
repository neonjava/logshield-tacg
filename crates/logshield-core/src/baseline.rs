use crate::event::{EventType, SecurityEvent};
use chrono::{DateTime, Timelike, Utc};
use std::collections::{HashMap, HashSet};
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct Baseline {
    pub users: HashMap<String, UserProfile>,
    pub common_services: HashSet<String>,
    pub normal_events_per_minute: f64,
}

impl Default for Baseline {
    fn default() -> Self {
        Self {
            users: HashMap::new(),
            common_services: HashSet::new(),
            normal_events_per_minute: 10.0,
        }
    }
}

#[derive(Debug, Default, Clone)]
pub struct UserProfile {
    pub hours: HashSet<u32>,
    pub hosts: HashSet<String>,
    pub source_ips: HashSet<String>,
    pub successful_logins: usize,
}

impl Baseline {
    /// Learn baseline profiles from trusted events without an explicit cutoff.
    pub fn learn(events: &[SecurityEvent]) -> Self {
        Self::learn_with_cutoff(events, None, None)
    }

    /// Train baseline profiles strictly on events prior to an optional `training_cutoff`.
    /// Events occurring after `training_cutoff` are strictly excluded to prevent evaluation leakage.
    /// Any events with IDs in `poison_exclusions` (e.g. active incidents or unverified activity)
    /// are also excluded to prevent threat actors from poisoning historical profiles.
    pub fn learn_with_cutoff(
        events: &[SecurityEvent],
        training_cutoff: Option<DateTime<Utc>>,
        poison_exclusions: Option<&HashSet<Uuid>>,
    ) -> Self {
        let mut b = Self {
            normal_events_per_minute: 10.0,
            ..Default::default()
        };
        for e in events {
            // Enforce explicit training time boundary
            if training_cutoff.is_some_and(|cutoff| e.timestamp > cutoff) {
                continue;
            }
            // Enforce poisoning exclusions
            if poison_exclusions.is_some_and(|exclusions| exclusions.contains(&e.id)) {
                continue;
            }
            // Exclude inherently suspicious or attack-phase event types
            if matches!(
                e.event_type,
                EventType::FailedLogin
                    | EventType::PasswordAccepted
                    | EventType::MfaFailure
                    | EventType::UnauthorizedAccess
                    | EventType::PrivilegeAction
                    | EventType::UnusualNetworkActivity
            ) {
                continue;
            }
            if let Some(s) = &e.service {
                b.common_services.insert(s.clone());
            }
            if let Some(u) = &e.username {
                let p = b.users.entry(u.clone()).or_default();
                if e.event_type == EventType::SuccessfulLogin {
                    p.successful_logins += 1;
                }
                p.hours.insert(e.timestamp.hour());
                if let Some(h) = &e.hostname {
                    p.hosts.insert(h.clone());
                }
                if let Some(ip) = &e.source_ip {
                    p.source_ips.insert(ip.clone());
                }
            }
        }
        b
    }

    /// Safely update an existing baseline with a newly verified, non-incident event.
    /// Returns false if the event is rejected (e.g. suspicious type or active incident association).
    pub fn safe_update(
        &mut self,
        event: &SecurityEvent,
        active_incident_event_ids: &HashSet<Uuid>,
    ) -> bool {
        if active_incident_event_ids.contains(&event.id) {
            return false;
        }
        if matches!(
            event.event_type,
            EventType::FailedLogin
                | EventType::PasswordAccepted
                | EventType::MfaFailure
                | EventType::UnauthorizedAccess
                | EventType::PrivilegeAction
                | EventType::UnusualNetworkActivity
        ) {
            return false;
        }
        if let Some(s) = &event.service {
            self.common_services.insert(s.clone());
        }
        if let Some(u) = &event.username {
            let p = self.users.entry(u.clone()).or_default();
            if event.event_type == EventType::SuccessfulLogin {
                p.successful_logins += 1;
            }
            p.hours.insert(event.timestamp.hour());
            if let Some(h) = &event.hostname {
                p.hosts.insert(h.clone());
            }
            if let Some(ip) = &event.source_ip {
                p.source_ips.insert(ip.clone());
            }
        }
        true
    }

    pub fn deviation(&self, events: &[SecurityEvent]) -> f64 {
        if events.is_empty() {
            return 0.0;
        }
        let mut novelty: f64 = 0.0;
        let mut checks = 0.0;
        for e in events {
            if let Some(u) = &e.username
                && let Some(p) = self.users.get(u)
            {
                checks += 1.0;
                let mut n: f64 = 0.0;
                if !p.hours.contains(&e.timestamp.hour()) {
                    n += 0.35;
                }
                if e.hostname.as_ref().is_some_and(|h| !p.hosts.contains(h)) {
                    n += 0.35;
                }
                if e.source_ip
                    .as_ref()
                    .is_some_and(|ip| !p.source_ips.contains(ip))
                {
                    n += 0.30;
                }
                novelty += n.min(1.0);
            }
        }
        let spike = ((events.len() as f64 / self.normal_events_per_minute) - 1.0).clamp(0.0, 1.0);
        ((if checks > 0.0 { novelty / checks } else { 0.0 }) * 0.55 + spike * 0.45).min(1.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    fn make_test_event(
        t: DateTime<Utc>,
        kind: EventType,
        ip: &str,
        host: &str,
        user: &str,
    ) -> SecurityEvent {
        let mut e = SecurityEvent::new(kind, t, ip, host);
        e.username = Some(user.into());
        e.service = Some("auth".into());
        e
    }

    #[test]
    fn test_learn_with_cutoff_strictly_excludes_future_events() {
        let t0 = Utc::now() - Duration::hours(2);
        let cutoff = t0 + Duration::hours(1);
        let t_future = cutoff + Duration::minutes(15);

        let historical_event = make_test_event(
            t0,
            EventType::SuccessfulLogin,
            "10.0.0.1",
            "host-a",
            "alice",
        );
        let future_eval_event = make_test_event(
            t_future,
            EventType::SuccessfulLogin,
            "10.0.0.99",
            "host-b",
            "alice",
        );

        let events = vec![historical_event, future_eval_event];
        let baseline = Baseline::learn_with_cutoff(&events, Some(cutoff), None);

        let alice = baseline.users.get("alice").expect("alice should exist");
        assert_eq!(alice.successful_logins, 1);
        assert!(alice.source_ips.contains("10.0.0.1"));
        // The evaluation event occurring after cutoff must NOT have leaked into the baseline
        assert!(!alice.source_ips.contains("10.0.0.99"));
        assert!(!alice.hosts.contains("host-b"));
    }

    #[test]
    fn test_poison_exclusions_blocks_active_incident_events() {
        let t0 = Utc::now();
        let e1 = make_test_event(
            t0,
            EventType::SuccessfulLogin,
            "10.0.0.1",
            "host-a",
            "alice",
        );
        let e2_malicious = make_test_event(
            t0 + Duration::minutes(1),
            EventType::SuccessfulLogin,
            "198.51.100.66",
            "host-a",
            "alice",
        );
        let mut exclusions = HashSet::new();
        exclusions.insert(e2_malicious.id);

        let baseline =
            Baseline::learn_with_cutoff(&[e1, e2_malicious.clone()], None, Some(&exclusions));
        let alice = baseline.users.get("alice").unwrap();
        assert_eq!(alice.successful_logins, 1);
        assert!(!alice.source_ips.contains("198.51.100.66"));

        // Safe update also rejects excluded event
        let mut live_baseline = baseline.clone();
        assert!(!live_baseline.safe_update(&e2_malicious, &exclusions));
    }

    #[test]
    fn test_cold_start_handling() {
        let baseline = Baseline::default();
        let e = make_test_event(
            Utc::now(),
            EventType::FailedLogin,
            "1.2.3.4",
            "h1",
            "unknown_user",
        );
        assert_eq!(baseline.deviation(&[e]), 0.0);
    }
}
