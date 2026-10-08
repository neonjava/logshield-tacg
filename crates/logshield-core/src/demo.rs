use crate::event::{EventType, SecurityEvent};
use chrono::{Duration, Utc};
pub fn scenario(name: &str) -> Vec<SecurityEvent> {
    let start = Utc::now() - Duration::seconds(65);
    let make = |second: i64, kind: EventType, source: &str, host: &str, user: &str| {
        let mut e = SecurityEvent::new(kind, start + Duration::seconds(second), source, host);
        e.username = Some(user.into());
        e.service = Some(
            if matches!(kind, EventType::UnusualNetworkActivity) {
                "network"
            } else {
                "ssh"
            }
            .into(),
        );
        e.port = Some(if matches!(kind, EventType::UnusualNetworkActivity) {
            4444
        } else {
            22
        });
        e.result = Some(
            if kind == EventType::FailedLogin {
                "failure"
            } else {
                "success"
            }
            .into(),
        );
        e.raw_message = format!("simulated {:?} on {host} for {user}", kind);
        e
    };
    match name {
        "normal" => vec![
            make(
                0,
                EventType::SuccessfulLogin,
                "10.0.0.11",
                "server-a",
                "alice",
            ),
            make(20, EventType::WebRequest, "10.0.0.12", "web-01", "bob"),
            make(
                40,
                EventType::ServiceActivity,
                "10.0.0.13",
                "server-b",
                "service",
            ),
        ],
        "bruteforce" => (0..8)
            .map(|i| {
                make(
                    i * 7,
                    EventType::FailedLogin,
                    "10.0.0.60",
                    "server-a",
                    "admin",
                )
            })
            .collect(),
        "distributed" => ["server-a", "server-a", "server-b", "server-b", "server-c"]
            .iter()
            .enumerate()
            .map(|(i, h)| {
                make(
                    i as i64 * 12,
                    EventType::FailedLogin,
                    "10.0.0.50",
                    h,
                    "admin",
                )
            })
            .collect(),
        "multistage" => [
            (0, EventType::Connection),
            (6, EventType::MultiPortActivity),
            (11, EventType::FailedLogin),
            (17, EventType::FailedLogin),
            (28, EventType::SuccessfulLogin),
            (34, EventType::PrivilegeAction),
            (41, EventType::UnusualNetworkActivity),
        ]
        .iter()
        .map(|(s, t)| make(*s, *t, "10.0.0.70", "server-01", "alice"))
        .collect(),
        _ => vec![],
    }
}
