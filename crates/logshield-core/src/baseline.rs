use crate::event::{EventType, SecurityEvent};
use chrono::{DateTime, Timelike, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Baseline {
    pub version: u64,
    pub users: HashMap<String, UserProfile>,
    pub common_services: HashSet<String>,
    pub normal_events_per_minute: f64,
    pub quarantine_seconds: i64,
    pub min_quarantine_observations: usize,
    pub frozen: bool,
    pub quarantined: HashMap<String, QuarantinedProfile>,
}

impl Default for Baseline {
    fn default() -> Self {
        Self {
            version: 1,
            users: HashMap::new(),
            common_services: HashSet::new(),
            normal_events_per_minute: 10.0,
            quarantine_seconds: 3600,
            min_quarantine_observations: 3,
            frozen: false,
            quarantined: HashMap::new(),
        }
    }
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct UserProfile {
    pub hours: HashSet<u32>,
    pub hosts: HashSet<String>,
    pub source_ips: HashSet<String>,
    pub successful_logins: usize,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct QuarantinedProfile {
    pub candidate_source_ips: HashMap<String, (DateTime<Utc>, usize)>,
    pub candidate_hosts: HashMap<String, (DateTime<Utc>, usize)>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaselineSnapshot {
    pub version: u64,
    pub created_at: DateTime<Utc>,
    pub quarantine_seconds: i64,
    pub min_quarantine_observations: usize,
    pub frozen: bool,
    pub users: HashMap<String, UserProfile>,
    pub common_services: HashSet<String>,
    pub normal_events_per_minute: f64,
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
    /// Returns false if the event is rejected (e.g. frozen baseline, suspicious type, or active incident association).
    pub fn safe_update(
        &mut self,
        event: &SecurityEvent,
        active_incident_event_ids: &HashSet<Uuid>,
    ) -> bool {
        if self.frozen {
            return false;
        }
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
        self.version += 1;
        true
    }

    /// Produce an immutable snapshot of the current baseline state.
    pub fn snapshot(&self) -> BaselineSnapshot {
        BaselineSnapshot {
            version: self.version,
            created_at: Utc::now(),
            quarantine_seconds: self.quarantine_seconds,
            min_quarantine_observations: self.min_quarantine_observations,
            frozen: self.frozen,
            users: self.users.clone(),
            common_services: self.common_services.clone(),
            normal_events_per_minute: self.normal_events_per_minute,
        }
    }

    /// Restore baseline profiles from a previously verified snapshot.
    pub fn restore_snapshot(&mut self, snapshot: BaselineSnapshot) {
        self.version = snapshot.version + 1;
        self.users = snapshot.users;
        self.common_services = snapshot.common_services;
        self.normal_events_per_minute = snapshot.normal_events_per_minute;
        self.quarantine_seconds = snapshot.quarantine_seconds;
        self.min_quarantine_observations = snapshot.min_quarantine_observations;
        self.frozen = snapshot.frozen;
        self.quarantined.clear();
    }

    /// Freeze the baseline to prevent any modifications (e.g. during active incident response or audit).
    pub fn freeze(&mut self) {
        self.frozen = true;
    }

    /// Unfreeze the baseline to resume safe updates.
    pub fn unfreeze(&mut self) {
        self.frozen = false;
    }

    /// Check if the baseline is currently frozen.
    pub fn is_frozen(&self) -> bool {
        self.frozen
    }

    /// Record a candidate observation into quarantine rather than promoting immediately.
    pub fn record_quarantine_observation(
        &mut self,
        user: &str,
        ip: Option<&str>,
        host: Option<&str>,
        now: DateTime<Utc>,
    ) {
        if self.frozen {
            return;
        }
        let q = self.quarantined.entry(user.to_string()).or_default();
        if let Some(ip_addr) = ip {
            let entry = q
                .candidate_source_ips
                .entry(ip_addr.to_string())
                .or_insert((now, 0));
            entry.1 += 1;
        }
        if let Some(hostname) = host {
            let entry = q
                .candidate_hosts
                .entry(hostname.to_string())
                .or_insert((now, 0));
            entry.1 += 1;
        }
    }

    /// Promote quarantined candidate IPs and hosts that satisfy the quarantine duration and observation thresholds.
    pub fn promote_quarantined(&mut self, now: DateTime<Utc>) -> usize {
        if self.frozen {
            return 0;
        }
        let mut promoted_count = 0;
        let quarantine_secs = self.quarantine_seconds;
        let min_obs = self.min_quarantine_observations;

        for (user, q) in &mut self.quarantined {
            let p = self.users.entry(user.clone()).or_default();
            q.candidate_source_ips.retain(|ip, (first_seen, obs)| {
                if (now - *first_seen).num_seconds() >= quarantine_secs && *obs >= min_obs {
                    p.source_ips.insert(ip.clone());
                    promoted_count += 1;
                    false
                } else {
                    true
                }
            });
            q.candidate_hosts.retain(|host, (first_seen, obs)| {
                if (now - *first_seen).num_seconds() >= quarantine_secs && *obs >= min_obs {
                    p.hosts.insert(host.clone());
                    promoted_count += 1;
                    false
                } else {
                    true
                }
            });
        }
        if promoted_count > 0 {
            self.version += 1;
        }
        promoted_count
    }

    /// Promote only the candidate explicitly reviewed by an operator. Observation
    /// counts and elapsed quarantine are prerequisites, never authorization.
    pub fn approve_quarantined(
        &mut self,
        user: &str,
        ip: &str,
        host: &str,
        now: DateTime<Utc>,
    ) -> bool {
        if self.frozen {
            return false;
        }
        if self
            .users
            .get(user)
            .is_some_and(|profile| profile.source_ips.contains(ip) && profile.hosts.contains(host))
        {
            return false;
        }
        let Some(q) = self.quarantined.get_mut(user) else {
            return false;
        };
        let ready = |candidate: Option<&(DateTime<Utc>, usize)>| {
            candidate.is_some_and(|(first, count)| {
                *count >= self.min_quarantine_observations
                    && (now - *first).num_seconds() >= self.quarantine_seconds
            })
        };
        if !ready(q.candidate_source_ips.get(ip)) || !ready(q.candidate_hosts.get(host)) {
            return false;
        }
        q.candidate_source_ips.remove(ip);
        q.candidate_hosts.remove(host);
        let profile = self.users.entry(user.to_owned()).or_default();
        profile.source_ips.insert(ip.to_owned());
        profile.hosts.insert(host.to_owned());
        profile.successful_logins = profile
            .successful_logins
            .max(self.min_quarantine_observations);
        self.version += 1;
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

    #[test]
    fn test_baseline_snapshot_and_restore() {
        let mut baseline = Baseline::default();
        let t0 = Utc::now();
        let e = make_test_event(
            t0,
            EventType::SuccessfulLogin,
            "10.0.0.5",
            "host-1",
            "charlie",
        );
        assert!(baseline.safe_update(&e, &HashSet::new()));
        assert_eq!(baseline.version, 2);

        let snap = baseline.snapshot();
        assert_eq!(snap.version, 2);
        assert!(snap.users.contains_key("charlie"));

        let mut restored = Baseline::default();
        restored.restore_snapshot(snap);
        assert_eq!(restored.version, 3);
        assert!(restored.users.contains_key("charlie"));
    }

    #[test]
    fn test_baseline_freeze_blocks_updates() {
        let mut baseline = Baseline::default();
        baseline.freeze();
        assert!(baseline.is_frozen());

        let t0 = Utc::now();
        let e = make_test_event(
            t0,
            EventType::SuccessfulLogin,
            "10.0.0.5",
            "host-1",
            "charlie",
        );
        assert!(!baseline.safe_update(&e, &HashSet::new()));
        assert!(!baseline.users.contains_key("charlie"));

        baseline.unfreeze();
        assert!(!baseline.is_frozen());
        assert!(baseline.safe_update(&e, &HashSet::new()));
        assert!(baseline.users.contains_key("charlie"));
    }

    #[test]
    fn test_quarantine_promotion_lifecycle() {
        let mut baseline = Baseline {
            quarantine_seconds: 60,
            min_quarantine_observations: 2,
            ..Default::default()
        };
        let t0 = Utc::now();

        // Observation 1: enters quarantine
        baseline.record_quarantine_observation("alice", Some("192.168.1.50"), Some("srv-1"), t0);
        let promoted = baseline.promote_quarantined(t0);
        assert_eq!(
            promoted, 0,
            "Should not promote before duration and min observations"
        );

        // Observation 2: count met, but time duration not elapsed
        baseline.record_quarantine_observation(
            "alice",
            Some("192.168.1.50"),
            Some("srv-1"),
            t0 + Duration::seconds(10),
        );
        let promoted = baseline.promote_quarantined(t0 + Duration::seconds(10));
        assert_eq!(
            promoted, 0,
            "Should not promote before quarantine_seconds has elapsed"
        );

        // After quarantine_seconds has elapsed:
        let promoted = baseline.promote_quarantined(t0 + Duration::seconds(65));
        assert_eq!(promoted, 2, "Should promote both IP and host");
        let alice = baseline.users.get("alice").unwrap();
        assert!(alice.source_ips.contains("192.168.1.50"));
        assert!(alice.hosts.contains("srv-1"));
    }
}
