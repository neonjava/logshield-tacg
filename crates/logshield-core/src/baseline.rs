use crate::event::{EventType, SecurityEvent};
use chrono::Timelike;
use std::collections::{HashMap, HashSet};

#[derive(Debug, Default, Clone)]
pub struct Baseline {
    pub users: HashMap<String, UserProfile>,
    pub common_services: HashSet<String>,
    pub normal_events_per_minute: f64,
}
#[derive(Debug, Default, Clone)]
pub struct UserProfile {
    pub hours: HashSet<u32>,
    pub hosts: HashSet<String>,
    pub source_ips: HashSet<String>,
    pub successful_logins: usize,
}
impl Baseline {
    pub fn learn(events: &[SecurityEvent]) -> Self {
        let mut b = Self {
            normal_events_per_minute: 10.0,
            ..Default::default()
        };
        for e in events {
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
