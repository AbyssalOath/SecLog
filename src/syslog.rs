// UDP/TCP syslog receiver -- lets firewalls, switches, and other
// devices that can't run the shipper still get events into SecLog.
//
// Security posture, stated up front: raw UDP/TCP syslog has no
// per-message authentication, industry-wide (rsyslog, syslog-ng,
// Graylog's syslog input all have the same property) -- this isn't a
// gap specific to this implementation. The mitigation used here,
// consistent with how those tools are actually deployed, is a
// source-IP/CIDR allowlist, fail-closed: an empty allowlist accepts
// nothing (see `ip_allowed`), not everything.
//
// The listeners themselves are bound once at startup (see main.rs) --
// like DATABASE_URL/FRONTEND_ORIGIN, this is an infra-level socket
// bind, so enabling/disabling or changing which protocols listen takes
// a server restart. The allowlist is NOT restart-gated: main.rs
// refreshes the shared `Arc<RwLock<Vec<String>>>` from the DB every
// 30s, so tightening/loosening source IPs takes effect live.

use crate::db::{self, DbPool};
use crate::models::Severity;
use crate::notify;
use crate::parser;
use regex::Regex;
use std::net::IpAddr;
use std::sync::{Arc, OnceLock};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::RwLock;

pub const SYSLOG_PORT: u16 = 514;
const MAX_UDP_PACKET: usize = 65535;

pub struct ParsedSyslogMessage {
    pub host: String,
    pub user: String,
    pub severity: Severity,
    pub message: String,
    pub event_time: Option<chrono::DateTime<chrono::Utc>>,
}

// Best-effort, not a guarantee -- same honesty already established for
// Directory sync's "likely enrolled" match. Real-world devices don't
// all follow RFC3164/RFC5424 precisely; anything that doesn't match
// either header shape still gets ingested, just with the source IP as
// its host and the whole line as its message, rather than being
// dropped.
pub fn parse_syslog_message(raw: &str, source_ip: &str) -> ParsedSyslogMessage {
    let raw = raw.trim_end_matches(['\r', '\n']);
    let after_pri = strip_pri(raw);
    let (host, body) = extract_header(after_pri, source_ip);

    let (severity, label) = parser::classify(body);
    let user = parser::extract_user(body);
    // extract_event_time tries an unanchored ISO8601 match (RFC5424)
    // before an anchored BSD-syslog match (RFC3164) -- `after_pri`
    // already starts right at whichever timestamp form the device
    // used, so this one call covers both without duplicating any of
    // parser.rs's existing timestamp-parsing regexes here.
    let event_time = parser::extract_event_time(after_pri);
    let message = format!("[{}] {}", label, body);

    ParsedSyslogMessage { host, user, severity, message, event_time }
}

fn strip_pri(line: &str) -> &str {
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| Regex::new(r"^<\d{1,3}>").unwrap());
    match re.find(line) {
        Some(m) => &line[m.end()..],
        None => line,
    }
}

// Tries RFC5424 ("1 TIMESTAMP HOST APP PROCID MSGID [SD] MSG") then
// RFC3164 ("Mmm dd hh:mm:ss HOST TAG: MSG"); falls back to treating the
// whole line as the message with the connection's source IP as the
// host, when neither header shape matches.
fn extract_header<'a>(text: &'a str, source_ip: &str) -> (String, &'a str) {
    static RFC5424_RE: OnceLock<Regex> = OnceLock::new();
    let rfc5424 = RFC5424_RE
        .get_or_init(|| Regex::new(r"^1\s+\S+\s+(\S+)\s+\S+\s+\S+\s+\S+\s+(.*)$").unwrap());
    if let Some(caps) = rfc5424.captures(text) {
        let hostname = caps.get(1).unwrap().as_str();
        let rest = caps.get(2).unwrap().as_str();
        let host = if hostname == "-" { source_ip.to_string() } else { hostname.to_string() };
        return (host, rest);
    }

    static RFC3164_RE: OnceLock<Regex> = OnceLock::new();
    let rfc3164 = RFC3164_RE
        .get_or_init(|| Regex::new(r"^[A-Z][a-z]{2}\s+\d{1,2}\s\d{2}:\d{2}:\d{2}\s+(\S+)\s+(.*)$").unwrap());
    if let Some(caps) = rfc3164.captures(text) {
        let hostname = caps.get(1).unwrap().as_str().to_string();
        let rest = caps.get(2).unwrap().as_str();
        return (hostname, rest);
    }

    (source_ip.to_string(), text)
}

// A bare entry with no "/prefix" is an exact-address match (implicit
// /32 or /128, picked from the CIDR entry's own address family, not
// the IP being tested against it).
pub fn ip_in_cidr(ip: &IpAddr, cidr: &str) -> bool {
    let cidr = cidr.trim();
    if cidr.is_empty() {
        return false;
    }
    let (net_part, prefix_part) = cidr.split_once('/').unwrap_or((cidr, ""));
    let Ok(net_ip) = net_part.parse::<IpAddr>() else { return false };
    let max_bits: u32 = match net_ip { IpAddr::V4(_) => 32, IpAddr::V6(_) => 128 };

    let prefix: u32 = if prefix_part.is_empty() {
        max_bits
    } else {
        match prefix_part.parse() {
            Ok(v) if v <= max_bits => v,
            _ => return false,
        }
    };

    match (ip, net_ip) {
        (IpAddr::V4(a), IpAddr::V4(b)) => {
            if prefix == 0 {
                return true;
            }
            let mask = u32::MAX << (32 - prefix);
            (u32::from(*a) & mask) == (u32::from(b) & mask)
        }
        (IpAddr::V6(a), IpAddr::V6(b)) => {
            if prefix == 0 {
                return true;
            }
            let mask = u128::MAX << (128 - prefix);
            (u128::from(*a) & mask) == (u128::from(b) & mask)
        }
        _ => false, // never match across address families
    }
}

// Fail-closed: an empty allowlist accepts nothing. The feature ships
// disabled by default and, once enabled, nothing is accepted until the
// admin adds at least one CIDR -- see the module comment above.
pub fn ip_allowed(ip: &IpAddr, allowlist: &[String]) -> bool {
    allowlist.iter().any(|c| ip_in_cidr(ip, c))
}

pub async fn run_udp_listener(pool: DbPool, allowlist: Arc<RwLock<Vec<String>>>) {
    let socket = match UdpSocket::bind(("0.0.0.0", SYSLOG_PORT)).await {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Syslog UDP listener failed to bind 0.0.0.0:{}: {}", SYSLOG_PORT, e);
            return;
        }
    };
    println!("Syslog UDP listener bound on 0.0.0.0:{}", SYSLOG_PORT);

    let mut buf = vec![0u8; MAX_UDP_PACKET];
    loop {
        let (n, src) = match socket.recv_from(&mut buf).await {
            Ok(v) => v,
            Err(e) => {
                eprintln!("Syslog UDP recv error: {}", e);
                continue;
            }
        };

        let source_ip = src.ip();
        if !ip_allowed(&source_ip, &allowlist.read().await) {
            continue; // silently dropped -- an open UDP port shouldn't log every scanner probe
        }

        let raw = String::from_utf8_lossy(&buf[..n]).into_owned();
        let pool = pool.clone();
        tokio::spawn(async move {
            ingest_syslog_message(&pool, &raw, &source_ip.to_string()).await;
        });
    }
}

pub async fn run_tcp_listener(pool: DbPool, allowlist: Arc<RwLock<Vec<String>>>) {
    let listener = match TcpListener::bind(("0.0.0.0", SYSLOG_PORT)).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("Syslog TCP listener failed to bind 0.0.0.0:{}: {}", SYSLOG_PORT, e);
            return;
        }
    };
    println!("Syslog TCP listener bound on 0.0.0.0:{}", SYSLOG_PORT);

    loop {
        let (stream, src) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                eprintln!("Syslog TCP accept error: {}", e);
                continue;
            }
        };

        let source_ip = src.ip();
        if !ip_allowed(&source_ip, &allowlist.read().await) {
            continue; // connection dropped immediately, nothing read from it
        }

        let pool = pool.clone();
        tokio::spawn(async move {
            let mut reader = BufReader::new(stream);
            let mut line = String::new();
            loop {
                line.clear();
                match reader.read_line(&mut line).await {
                    Ok(0) => break, // connection closed
                    Ok(_) => {
                        let trimmed = line.trim_end_matches(['\r', '\n']);
                        if !trimmed.is_empty() {
                            ingest_syslog_message(&pool, trimmed, &source_ip.to_string()).await;
                        }
                    }
                    Err(e) => {
                        eprintln!("Syslog TCP read error from {}: {}", source_ip, e);
                        break;
                    }
                }
            }
        });
    }
}

// Mirrors create_log's dedup-hash-insert-then-alert sequence in
// main.rs -- deliberately not factored into one shared helper the two
// call, since the surrounding context (an authenticated agent request
// vs. a raw network listener with no HTTP status code to return)
// genuinely differs and the shared part is only a few lines.
async fn ingest_syslog_message(pool: &DbPool, raw: &str, source_ip: &str) {
    if raw.trim().is_empty() {
        return;
    }

    let parsed = parse_syslog_message(raw, source_ip);
    let severity = format!("{:?}", parsed.severity);
    let event_time = parser::sanitize_event_time(parsed.event_time);

    if let Some(et) = event_time {
        let skew = (chrono::Utc::now() - et).num_minutes().abs();
        if skew > parser::EVENT_TIME_SKEW_WARN_MINUTES {
            eprintln!(
                "Clock skew: syslog source {} ({}) reported an event {} min from server time (event_time={})",
                parsed.host, source_ip, skew, et
            );
        }
        if skew > parser::EVENT_TIME_SKEW_ALERT_MINUTES {
            let pool = pool.clone();
            let host = parsed.host.clone();
            tokio::spawn(async move {
                notify::trigger_alert(
                    &pool, "Medium",
                    &format!("[SYSTEM] Clock skew of {} minutes detected -- check NTP on this host", skew),
                    &host,
                ).await;
            });
        }
    }

    let combined = format!("{}{}{}{}", severity, parsed.user, parsed.message, parsed.host);
    let hash = parser::hash_line(&combined);

    match db::insert_log(pool, &severity, &parsed.user, &parsed.message, &parsed.host, &hash, event_time).await {
        Ok(true) => {
            let pool = pool.clone();
            let message = parsed.message.clone();
            let host = parsed.host.clone();
            tokio::spawn(async move {
                notify::trigger_alert(&pool, &severity, &message, &host).await;
            });
        }
        Ok(false) => {} // duplicate line, already ingested -- same dedup as the shipper's own retries
        Err(e) => eprintln!("Syslog: DB insert error: {}", e),
    }

    if let Err(e) = db::touch_syslog_last_message(pool, &parsed.host).await {
        eprintln!("Syslog: failed to record last-message stats: {}", e);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_rfc3164_message() {
        // Classic BSD-syslog example (RFC 3164 §5.4).
        let raw = "<34>Oct 11 22:14:15 mymachine su: 'su root' failed for lonvick on /dev/pts/8";
        let parsed = parse_syslog_message(raw, "10.0.0.5");
        assert_eq!(parsed.host, "mymachine");
        assert!(parsed.message.contains("'su root' failed for lonvick"));
        assert!(parsed.event_time.is_some());
    }

    #[test]
    fn parses_rfc5424_message() {
        // RFC 5424 §6.5 example, with nil structured data.
        let raw = "<34>1 2003-10-11T22:14:15.003Z mymachine.example.com su - ID47 - 'su root' failed for lonvick on /dev/pts/8";
        let parsed = parse_syslog_message(raw, "10.0.0.5");
        assert_eq!(parsed.host, "mymachine.example.com");
        assert!(parsed.message.contains("'su root' failed for lonvick"));
        let et = parsed.event_time.expect("should parse RFC5424 timestamp");
        assert_eq!(et.timestamp(), 1065910455);
    }

    #[test]
    fn falls_back_to_source_ip_when_header_unrecognized() {
        let raw = "just some plain text a minimal device might send";
        let parsed = parse_syslog_message(raw, "192.0.2.9");
        assert_eq!(parsed.host, "192.0.2.9");
        assert!(parsed.message.ends_with(raw));
    }

    #[test]
    fn ip_in_cidr_matches_ipv4_ranges() {
        let ip: IpAddr = "10.1.2.3".parse().unwrap();
        assert!(ip_in_cidr(&ip, "10.0.0.0/8"));
        assert!(ip_in_cidr(&ip, "10.1.2.3")); // bare address, implicit /32
        assert!(ip_in_cidr(&ip, "10.1.2.3/32"));
        assert!(!ip_in_cidr(&ip, "10.1.2.4/32"));
        assert!(!ip_in_cidr(&ip, "192.168.0.0/16"));
    }

    #[test]
    fn ip_in_cidr_matches_ipv6_ranges() {
        let ip: IpAddr = "2001:db8::1".parse().unwrap();
        assert!(ip_in_cidr(&ip, "2001:db8::/32"));
        assert!(!ip_in_cidr(&ip, "2001:db9::/32"));
        assert!(!ip_in_cidr(&ip, "10.0.0.0/8")); // never matches across families
    }

    #[test]
    fn ip_allowed_is_fail_closed_on_empty_list() {
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        assert!(!ip_allowed(&ip, &[]));
        assert!(ip_allowed(&ip, &["10.0.0.0/8".to_string()]));
    }
}
