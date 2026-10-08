use crate::event::{EventType, SecurityEvent};
use chrono::{DateTime, Datelike, NaiveDateTime, TimeZone, Utc};

pub fn parse_line(line: &str) -> Result<SecurityEvent, String> {
    let line = line.trim();
    if line.is_empty() || line.len() > 16_384 {
        return Err("empty or oversized log line".into());
    }
    if line.starts_with('{') {
        return serde_json::from_str::<SecurityEvent>(line)
            .map_err(|e| format!("invalid JSON event: {e}"));
    }
    let lower = line.to_ascii_lowercase();
    let event_type =
        if lower.contains("failed password") || lower.contains("authentication failure") {
            EventType::FailedLogin
        } else if lower.contains("accepted password") || lower.contains("accepted publickey") {
            EventType::SuccessfulLogin
        } else if lower.contains("sudo:") || lower.contains("privilege") {
            EventType::PrivilegeAction
        } else if lower.contains("unauthorized") || lower.contains("denied") {
            EventType::UnauthorizedAccess
        } else if lower.contains("outbound") || lower.contains("exfil") {
            EventType::UnusualNetworkActivity
        } else if lower.contains("dpt=") || lower.contains("spt=") || lower.contains("firewall") {
            EventType::Connection
        } else {
            return Err("unrecognized log format".into());
        };
    let timestamp = parse_timestamp(line).unwrap_or_else(Utc::now);
    let mut event = SecurityEvent::new(event_type, timestamp, "", "");
    event.source_ip = field(line, "SRC=").or_else(|| word_after(line, "from "));
    event.destination_ip = field(line, "DST=");
    event.hostname = line
        .split_whitespace()
        .nth(3)
        .filter(|_| !line.contains("SRC="))
        .map(str::to_owned);
    event.username =
        word_after(line, "for ").map(|s| if s == "invalid" { "unknown".into() } else { s });
    event.port = field(line, "DPT=")
        .and_then(|x| x.parse().ok())
        .or_else(|| word_after(line, "port ").and_then(|x| x.parse().ok()));
    event.service = Some(
        if line.contains("sshd") {
            "ssh"
        } else {
            "network"
        }
        .into(),
    );
    event.result = Some(
        if event_type == EventType::FailedLogin || event_type == EventType::UnauthorizedAccess {
            "failure"
        } else {
            "success"
        }
        .into(),
    );
    event.raw_message = line.into();
    Ok(event)
}
fn field(line: &str, key: &str) -> Option<String> {
    line.split_whitespace()
        .find_map(|part| part.strip_prefix(key).map(str::to_owned))
}
fn word_after(line: &str, marker: &str) -> Option<String> {
    line.split_once(marker)
        .and_then(|(_, rest)| rest.split_whitespace().next())
        .map(|s| s.trim_end_matches(':').to_owned())
}
fn parse_timestamp(line: &str) -> Option<DateTime<Utc>> {
    if let Some(first) = line.split_whitespace().next()
        && let Ok(t) = DateTime::parse_from_rfc3339(first)
    {
        return Some(t.with_timezone(&Utc));
    }
    let prefix = line.get(..15)?;
    let year = Utc::now().year();
    let naive =
        NaiveDateTime::parse_from_str(&format!("{year} {prefix}"), "%Y %b %e %H:%M:%S").ok()?;
    Some(Utc.from_utc_datetime(&naive))
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ssh_and_firewall() {
        let a=parse_line("Oct  8 10:04:12 server-a sshd[123]: Failed password for alice from 10.0.0.50 port 51234 ssh2").unwrap();
        assert_eq!(a.event_type, EventType::FailedLogin);
        assert_eq!(a.source_ip.as_deref(), Some("10.0.0.50"));
        let b =
            parse_line("2026-10-08T10:04:01Z firewall SRC=10.0.0.50 DST=10.0.0.1 DPT=22 DENIED")
                .unwrap();
        assert_eq!(b.port, Some(22));
    }
}
