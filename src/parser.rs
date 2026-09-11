use crate::models::{LogEntry, Severity};
use chrono::{DateTime, Datelike, NaiveDate, TimeZone, Utc};
use sha2::{Digest, Sha256};
use regex::Regex;
use std::sync::OnceLock;

// A single detection rule: if `pattern` matches a line, that line gets
// `severity` and a human-readable `label` describing what was detected.
// This is the same basic mechanism real tools like Wazuh use under the
// hood -- a maintained table of known-meaningful patterns. Ours starts
// small and is meant to grow over time.
struct Rule {
    pattern: Regex,
    severity: Severity,
    label: &'static str,
}

// ORDERING RULE, read before adding anything:
// Rules are checked top to bottom; the FIRST match wins. So:
//   1. More SPECIFIC patterns must come before more GENERAL ones that
//      could also match the same text (e.g. "disconnect by invalid user"
//      must come before the bare "Invalid user" rule, or the specific
//      label/severity never gets a chance to apply).
//   2. Within a category, put the rarer/more severe pattern first.
//   3. Broad catch-all patterns (single keywords, wide OR-groups like
//      "DENY|DROP") belong at the END of their category, since they're
//      the most likely to accidentally swallow a more specific case
//      placed after them.
//   4. When adding a new rule, ask: "could an EXISTING broad rule below
//      this category already match my new pattern's text?" If yes, your
//      new rule needs to go above that broad rule, not just at the end
//      of the file.
fn rules() -> &'static Vec<Rule> {
    static RULES: OnceLock<Vec<Rule>> = OnceLock::new();
    RULES.get_or_init(|| {
        vec![
            // --- Critical: tampering / evidence destruction ---
            // Always keep this section first -- these represent an attacker
            // actively covering their tracks, the highest-value signal we have.
            Rule { pattern: Regex::new(r"(?i)EventID=1102").unwrap(), severity: Severity::Critical, label: "Audit log cleared" },
            Rule { pattern: Regex::new(r"(?i)history -c|unset HISTFILE").unwrap(), severity: Severity::High, label: "Shell history cleared/disabled" },

            // --- Linux audit subsystem (auditd) ---
            // These come from the kernel audit framework itself (type=XXX lines),
            // a different source than syslog/auth.log text. Distinguishing
            // res=success from res=failed on the same event type matters --
            // treating them identically was leaving failed logins misclassified
            // as "Unclassified" alongside routine session teardown noise.
            Rule { pattern: Regex::new(r"type=USER_LOGIN.*res=failed").unwrap(), severity: Severity::Medium, label: "Failed login (audit)" },
            Rule { pattern: Regex::new(r"type=USER_LOGIN.*res=success").unwrap(), severity: Severity::Low, label: "Successful login (audit)" },
            Rule { pattern: Regex::new(r"type=CRYPTO_KEY_USER.*res=success").unwrap(), severity: Severity::Low, label: "SSH session key teardown (routine)" },
            Rule { pattern: Regex::new(r"type=CRYPTO_KEY_USER").unwrap(), severity: Severity::Low, label: "SSH crypto key event" },
            Rule { pattern: Regex::new(r"type=USER_START").unwrap(), severity: Severity::Low, label: "Session started (audit)" },
            Rule { pattern: Regex::new(r"type=USER_END").unwrap(), severity: Severity::Low, label: "Session ended (audit)" },

            // --- SSH / remote access ---
            // Specific phrasing first, generic "Invalid user"/"Failed password"
            // last since several other patterns' text also contains those words.
            Rule { pattern: Regex::new(r"(?i)authorized_keys").unwrap(), severity: Severity::High, label: "SSH authorized_keys modified" },
            Rule { pattern: Regex::new(r"(?i)maximum authentication attempts exceeded").unwrap(), severity: Severity::High, label: "SSH max auth attempts exceeded" },
            Rule { pattern: Regex::new(r"(?i)disconnect(ed)? by invalid user").unwrap(), severity: Severity::High, label: "SSH invalid user disconnect" },
            Rule { pattern: Regex::new(r"(?i)Repeated login failures").unwrap(), severity: Severity::High, label: "Repeated login failures" },
            Rule { pattern: Regex::new(r"Invalid user").unwrap(), severity: Severity::High, label: "SSH invalid user attempt" },
            Rule { pattern: Regex::new(r"Failed password").unwrap(), severity: Severity::High, label: "SSH failed login" },
            Rule { pattern: Regex::new(r"(?i)authentication failure").unwrap(), severity: Severity::Medium, label: "Authentication failure" },
            Rule { pattern: Regex::new(r"Accepted password|Accepted publickey").unwrap(), severity: Severity::Low, label: "SSH successful login" },
            Rule { pattern: Regex::new(r"(?i)Received disconnect.*11:").unwrap(), severity: Severity::Low, label: "SSH client disconnect" },

            // --- Sudo / su / privilege escalation ---
            // "NOT in sudoers" and su-specific rules first; the broad
            // "sudo:.*COMMAND=" catch-all (matches EVERY routine sudo use)
            // must stay last in this category.
            Rule { pattern: Regex::new(r"(?i)NOT in sudoers").unwrap(), severity: Severity::High, label: "Unauthorized sudo attempt" },
            Rule { pattern: Regex::new(r"(?i)su:.*FAILED").unwrap(), severity: Severity::High, label: "su failed attempt" },
            Rule { pattern: Regex::new(r"(?i)su:.*session opened").unwrap(), severity: Severity::Medium, label: "su session opened" },
            Rule { pattern: Regex::new(r"(?i)incorrect password").unwrap(), severity: Severity::High, label: "Sudo failed attempt" },
            Rule { pattern: Regex::new(r"sudo:.*COMMAND=").unwrap(), severity: Severity::Low, label: "Sudo command executed" },

            // --- Account & group management ---
            Rule { pattern: Regex::new(r"(?i)session opened for user root").unwrap(), severity: Severity::Medium, label: "Root session opened" },
            Rule { pattern: Regex::new(r"(?i)added to group").unwrap(), severity: Severity::Medium, label: "Group membership changed" },
            Rule { pattern: Regex::new(r"(?i)removed from group").unwrap(), severity: Severity::Medium, label: "Group membership changed" },
            Rule { pattern: Regex::new(r"(?i)useradd|userdel|usermod").unwrap(), severity: Severity::Medium, label: "User account modified" },
            Rule { pattern: Regex::new(r"(?i)passwd:").unwrap(), severity: Severity::Medium, label: "Password changed" },

            // --- Firewall / network ---
            // Port scan indicators first (specific + high severity); the
            // broad "DENY|DROP" keyword pair last, since tons of routine
            // firewall log lines contain those words.
            Rule { pattern: Regex::new(r"(?i)port scan|nmap").unwrap(), severity: Severity::High, label: "Possible port scan" },
            Rule { pattern: Regex::new(r"(?i)connection refused").unwrap(), severity: Severity::Low, label: "Connection refused" },
            Rule { pattern: Regex::new(r"(?i)iptables|ufw|firewalld").unwrap(), severity: Severity::Medium, label: "Firewall event" },
            Rule { pattern: Regex::new(r"(?i)DENY|DROP").unwrap(), severity: Severity::Medium, label: "Firewall deny/drop" },

            // --- System integrity ---
            Rule { pattern: Regex::new(r"(?i)\.bash_history").unwrap(), severity: Severity::Medium, label: "Shell history file accessed" },
            Rule { pattern: Regex::new(r"(?i)crontab").unwrap(), severity: Severity::Medium, label: "Cron job modified" },
            Rule { pattern: Regex::new(r"(?i)segfault").unwrap(), severity: Severity::Medium, label: "Segmentation fault" },
            Rule { pattern: Regex::new(r"(?i)systemd\[1\]: Started").unwrap(), severity: Severity::Low, label: "Service started" },

            // --- macOS-specific ---
            Rule { pattern: Regex::new(r"(?i)Gatekeeper.*blocked").unwrap(), severity: Severity::High, label: "macOS Gatekeeper blocked app" },
            Rule { pattern: Regex::new(r"(?i)codesign.*invalid").unwrap(), severity: Severity::High, label: "macOS code signature invalid" },
            Rule { pattern: Regex::new(r"(?i)Sender Authentication Failed").unwrap(), severity: Severity::High, label: "macOS auth failure" },
            Rule { pattern: Regex::new(r"(?i)TCC.*denied").unwrap(), severity: Severity::Medium, label: "macOS privacy permission denied" },

            // --- Windows EventID coverage ---
            // (For text flowing through this generic parser, e.g. if raw
            // wevtutil output ever gets tailed as a file. The dedicated
            // Windows shipper path uses classify_event_id() directly instead.)
            // Ordered by severity: lockout/privileged-group first, then
            // failed logon, then routine account creation last.
            Rule { pattern: Regex::new(r"(?i)EventID=4740").unwrap(), severity: Severity::High, label: "Account lockout" },
            Rule { pattern: Regex::new(r"(?i)EventID=4732").unwrap(), severity: Severity::High, label: "Windows user added to privileged group" },
            Rule { pattern: Regex::new(r"(?i)EventID=4625").unwrap(), severity: Severity::High, label: "Windows failed logon" },
            Rule { pattern: Regex::new(r"(?i)EventID=4720").unwrap(), severity: Severity::Medium, label: "Windows account created" },
        ]
    })
}

// Tries several known patterns to pull a username out of a raw syslog
// line. Falls back to "system" when no pattern matches -- many valid
// security-relevant lines (kernel messages, firewall drops) have no
// associated user at all. `pub` so the syslog receiver (src/syslog.rs)
// can reuse the exact same extraction logic instead of duplicating it.
pub fn extract_user(line: &str) -> String {
    static USER_PATTERNS: OnceLock<Vec<Regex>> = OnceLock::new();
    let patterns = USER_PATTERNS.get_or_init(|| {
        vec![
            Regex::new(r"Failed password for (?:invalid user )?(\S+) from").unwrap(),
            Regex::new(r"Invalid user (\S+) from").unwrap(),
            Regex::new(r"Accepted (?:password|publickey) for (\S+) from").unwrap(),
            Regex::new(r"sudo:\s*(\S+)\s*:").unwrap(),
        ]
    });

    for re in patterns {
        if let Some(caps) = re.captures(line)
            && let Some(m) = caps.get(1)
        {
            return m.as_str().to_string();
        }
    }

    "system".to_string()
}

// The actual rule-matching pass, pulled out of parse_line so the syslog
// receiver (src/syslog.rs) can classify a message body the same way a
// shipper-sourced line is classified, without duplicating this loop or
// risking the two classification paths drifting apart.
pub fn classify(text: &str) -> (Severity, &'static str) {
    for rule in rules() {
        if rule.pattern.is_match(text) {
            return (rule.severity.clone(), rule.label);
        }
    }
    (Severity::Low, "Unclassified")
}

// Every distinct label in the rule table, in table order with
// duplicates removed -- backs the correlation-rules admin UI's label
// picker (a `<select>`, not free text: see README/ARCHITECTURE for why
// correlation rules deliberately can't reference an arbitrary pattern).
pub fn known_labels() -> Vec<&'static str> {
    let mut seen = std::collections::HashSet::new();
    rules()
        .iter()
        .map(|r| r.label)
        .filter(|label| seen.insert(*label))
        .collect()
}

// Now accepts essentially ANY non-empty line -- real security logs
// (auth.log, journalctl output, etc.) don't follow one fixed format,
// so instead of requiring a specific shape, we classify whatever comes
// in using the rule table above.
pub fn parse_line(line: &str) -> Option<LogEntry> {
    if line.trim().is_empty() {
        return None;
    }

    let user = extract_user(line);
    let (severity, label) = classify(line);

    // Prefix the detection label onto the stored message, so it's visible
    // in the dashboard without needing a whole new DB column right now.
    let message = format!("[{}] {}", label, line);
    let event_time = extract_event_time(line);

    Some(LogEntry { severity, user, message, event_time })
}

// Tries to recover the ORIGINAL event time embedded in a raw log line,
// as opposed to when SecLog happens to ingest it -- CJIS AU-8 cares
// about this distinction specifically (a shipper catching up on a
// backlog after an outage would otherwise report everything clustered
// near catch-up time, not when it actually happened). Tried in order
// from most to least reliable; first match wins, same spirit as the
// classification rules above. `None` means no recognized timestamp was
// found in the line -- the caller falls back to ingestion time.
pub fn extract_event_time(line: &str) -> Option<DateTime<Utc>> {
    extract_auditd_time(line)
        .or_else(|| extract_iso8601_time(line))
        .or_else(|| extract_bsd_syslog_time(line))
}

// CJIS AU-8: an event_time more than this far in either direction from
// the server's own clock is loud-logged; past the larger threshold it
// also fires a [SYSTEM] alert -- a strong, simple signal that a
// monitored host's clock (or SecLog's own) has drifted from NTP. Shared
// by both ingestion paths that accept a caller-reported event_time
// (the shipper's `create_log` in main.rs, and the syslog receiver in
// syslog.rs), so the two can't silently drift to different thresholds.
pub const EVENT_TIME_SKEW_WARN_MINUTES: i64 = 15;
pub const EVENT_TIME_SKEW_ALERT_MINUTES: i64 = 60;

// A caller-reported event_time is trusted input from an authenticated
// agent or an allowlisted syslog source, not attacker-controlled in any
// new way -- this is just a sanity bound against a garbled parse (e.g.
// a mis-extracted auditd timestamp), not a security boundary. Anything
// outside a generous [2000-01-01, now+1 day] range is treated as
// unparseable.
pub fn sanitize_event_time(event_time: Option<DateTime<Utc>>) -> Option<DateTime<Utc>> {
    let et = event_time?;
    let now = Utc::now();
    let earliest = DateTime::parse_from_rfc3339("2000-01-01T00:00:00Z").unwrap().with_timezone(&Utc);
    if et < earliest || et > now + chrono::Duration::days(1) {
        None
    } else {
        Some(et)
    }
}

// auditd: "...audit(1699999999.123:456): ..." -- unambiguous epoch
// seconds + milliseconds, no year-inference needed. The most reliable
// source available, and already a first-class input to this parser
// (see the type=USER_LOGIN etc. rules above).
fn extract_auditd_time(line: &str) -> Option<DateTime<Utc>> {
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| Regex::new(r"audit\((\d+)\.(\d+):\d+\)").unwrap());
    let caps = re.captures(line)?;
    let secs: i64 = caps.get(1)?.as_str().parse().ok()?;
    let millis: u32 = caps.get(2)?.as_str().parse().ok()?;
    Utc.timestamp_opt(secs, millis * 1_000_000).single()
}

// A leading RFC3339/ISO8601 timestamp, e.g. from journald exports or a
// syslog daemon configured for it: "2026-09-11T14:23:00Z ..." or
// "...T14:23:00-05:00 ...". A timezone-less match is treated as UTC.
// Covers both RFC3339-strict lines (journald exports, wevtutil's
// "Date:" field: "2026-09-11T14:23:00.1234567Z") AND the format macOS's
// `log stream --style syslog` actually emits: a SPACE instead of 'T',
// and a timezone offset with no colon ("2026-09-11 14:23:00.123456
// -0500"). `chrono::DateTime::parse_from_rfc3339` rejects the latter
// outright (it requires exact RFC3339 punctuation), which is why this
// builds the timestamp manually from capture groups instead of leaning
// on that parser -- string-rewriting into strict RFC3339 first would
// work too, but parsing the fields directly is less fragile than
// hoping every real-world variant survives a rewrite step.
fn extract_iso8601_time(line: &str) -> Option<DateTime<Utc>> {
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| {
        Regex::new(
            r"(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?[ ]?(Z|[+-]\d{2}:?\d{2})?",
        )
        .unwrap()
    });
    let caps = re.captures(line)?;

    let year: i32 = caps.get(1)?.as_str().parse().ok()?;
    let month: u32 = caps.get(2)?.as_str().parse().ok()?;
    let day: u32 = caps.get(3)?.as_str().parse().ok()?;
    let hour: u32 = caps.get(4)?.as_str().parse().ok()?;
    let minute: u32 = caps.get(5)?.as_str().parse().ok()?;
    let second: u32 = caps.get(6)?.as_str().parse().ok()?;

    // Fractional seconds can be any number of digits (wevtutil uses 7,
    // macOS uses 6) -- pad or truncate to exactly 6 (microseconds).
    let micros: u32 = match caps.get(7) {
        Some(m) => {
            let s = m.as_str();
            let padded: String = s.chars().chain(std::iter::repeat('0')).take(6).collect();
            padded.parse().ok()?
        }
        None => 0,
    };

    let date = NaiveDate::from_ymd_opt(year, month, day)?;
    let naive = date.and_hms_micro_opt(hour, minute, second, micros)?;

    // The matched timestamp is a LOCAL time at some offset from UTC
    // (or already UTC, if "Z" or no offset at all) -- shift by the
    // offset to get the true UTC instant. A "+05:00"-stamped 14:00 is
    // 09:00 UTC, hence subtracting, not adding.
    let offset_minutes: i64 = match caps.get(8).map(|m| m.as_str()) {
        None | Some("Z") => 0,
        Some(tz) => {
            let sign: i64 = if tz.starts_with('-') { -1 } else { 1 };
            let digits: String = tz.chars().filter(|c| c.is_ascii_digit()).collect();
            if digits.len() < 4 {
                return None;
            }
            let hh: i64 = digits[0..2].parse().ok()?;
            let mm: i64 = digits[2..4].parse().ok()?;
            sign * (hh * 60 + mm)
        }
    };

    let utc_naive = naive - chrono::Duration::minutes(offset_minutes);
    Some(Utc.from_utc_datetime(&utc_naive))
}

// Classic BSD syslog, the default format for auth.log/secure:
// "Sep 11 14:23:00 host proc[pid]: ...". The format itself carries no
// year -- assumed to be the current one, stepping back a year if that
// would place the event in the future. "In the future" is a much
// stronger, simpler tell than any calendar-boundary math, and correctly
// handles a shipper catching up on a backlog that spans New Year's.
fn extract_bsd_syslog_time(line: &str) -> Option<DateTime<Utc>> {
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| Regex::new(r"^([A-Z][a-z]{2})\s+(\d{1,2})\s(\d{2}):(\d{2}):(\d{2})").unwrap());
    let caps = re.captures(line)?;

    let month = month_from_abbrev(caps.get(1)?.as_str())?;
    let day: u32 = caps.get(2)?.as_str().parse().ok()?;
    let hour: u32 = caps.get(3)?.as_str().parse().ok()?;
    let minute: u32 = caps.get(4)?.as_str().parse().ok()?;
    let second: u32 = caps.get(5)?.as_str().parse().ok()?;

    let build = |year: i32| -> Option<DateTime<Utc>> {
        let date = NaiveDate::from_ymd_opt(year, month, day)?;
        let naive = date.and_hms_opt(hour, minute, second)?;
        Some(Utc.from_utc_datetime(&naive))
    };

    let now = Utc::now();
    let this_year = build(now.year())?;
    if this_year > now + chrono::Duration::days(1) {
        build(now.year() - 1)
    } else {
        Some(this_year)
    }
}

fn month_from_abbrev(s: &str) -> Option<u32> {
    Some(match s {
        "Jan" => 1, "Feb" => 2, "Mar" => 3, "Apr" => 4, "May" => 5, "Jun" => 6,
        "Jul" => 7, "Aug" => 8, "Sep" => 9, "Oct" => 10, "Nov" => 11, "Dec" => 12,
        _ => return None,
    })
}

pub fn hash_line(line: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(line.as_bytes());
    let result = hasher.finalize();
    result.iter().map(|b| format!("{:02x}", b)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Datelike, Timelike};

    #[test]
    fn extracts_auditd_epoch_time() {
        // 1699999999.123 -> 2023-11-14T22:33:19.123Z
        let line = "type=USER_LOGIN msg=audit(1699999999.123:456): res=success";
        let et = extract_event_time(line).expect("should parse auditd timestamp");
        assert_eq!(et.timestamp(), 1699999999);
        assert_eq!(et.timestamp_subsec_millis(), 123);
    }

    #[test]
    fn extracts_iso8601_time() {
        let line = "2026-01-15T14:23:00Z host sshd[123]: Accepted password for root";
        let et = extract_event_time(line).expect("should parse ISO8601 timestamp");
        assert_eq!(et.year(), 2026);
        assert_eq!(et.month(), 1);
        assert_eq!(et.day(), 15);
        assert_eq!(et.hour(), 14);
    }

    #[test]
    fn extracts_macos_log_stream_time() {
        // `log stream --style syslog`'s actual format: space instead of
        // 'T', and a timezone offset with no colon.
        let line = "2026-09-11 14:23:00.123456-0500 host sudo[123]: user1 : COMMAND=/bin/ls";
        let et = extract_event_time(line).expect("should parse macOS syslog-style timestamp");
        assert_eq!(et.year(), 2026);
        assert_eq!(et.month(), 9);
        assert_eq!(et.day(), 11);
        // 14:23 at -05:00 is 19:23 UTC.
        assert_eq!(et.hour(), 19);
        assert_eq!(et.minute(), 23);
    }

    #[test]
    fn extracts_wevtutil_date_field() {
        // wevtutil's "Date:" field, 7 fractional digits (100ns ticks,
        // truncated here to microsecond precision).
        let block = "Event[0]:\n  Log Name: Security\n  Date: 2026-09-11T14:23:00.1234567Z\n  Event ID: 4625";
        let et = extract_event_time(block).expect("should parse wevtutil Date field");
        assert_eq!(et.year(), 2026);
        assert_eq!(et.hour(), 14);
        assert_eq!(et.minute(), 23);
    }

    #[test]
    fn iso8601_offset_with_colon_still_works() {
        let line = "2026-09-11T14:23:00+05:30 some message";
        let et = extract_event_time(line).expect("should parse a colon-separated offset");
        // 14:23 at +05:30 is 08:53 UTC.
        assert_eq!(et.hour(), 8);
        assert_eq!(et.minute(), 53);
    }

    #[test]
    fn extracts_bsd_syslog_time_current_year() {
        // A BSD syslog line dated well in the past relative to "now" --
        // should resolve to the current year, not roll back.
        let line = "Jan  5 03:24:00 host sshd[123]: Failed password for root from 1.2.3.4";
        let et = extract_event_time(line).expect("should parse BSD syslog timestamp");
        assert_eq!(et.month(), 1);
        assert_eq!(et.day(), 5);
        assert_eq!(et.hour(), 3);
        assert_eq!(et.year(), Utc::now().year());
    }

    #[test]
    fn bsd_syslog_time_rolls_back_a_year_when_future() {
        // Dec 31 interpreted in the current year is virtually always
        // "in the future" relative to whenever this test actually runs
        // (the only exception being the last day of the year itself) --
        // exactly the backlog-across-New-Year's scenario this logic
        // exists for. Should resolve to LAST year, not the current one.
        let line = "Dec 31 23:59:00 host sshd[123]: Accepted password for root";
        let et = extract_event_time(line).expect("should parse BSD syslog timestamp");
        let now = Utc::now();
        if now.month() == 12 && now.day() == 31 {
            return; // can't meaningfully assert "in the future" today
        }
        assert_eq!(et.year(), now.year() - 1);
    }

    #[test]
    fn no_recognized_timestamp_returns_none() {
        let line = "some ordinary log line with no timestamp at all";
        assert!(extract_event_time(line).is_none());
    }

    #[test]
    fn month_abbreviations_cover_all_twelve() {
        for (abbrev, expected) in [
            ("Jan", 1), ("Feb", 2), ("Mar", 3), ("Apr", 4), ("May", 5), ("Jun", 6),
            ("Jul", 7), ("Aug", 8), ("Sep", 9), ("Oct", 10), ("Nov", 11), ("Dec", 12),
        ] {
            assert_eq!(month_from_abbrev(abbrev), Some(expected));
        }
        assert_eq!(month_from_abbrev("Xyz"), None);
    }

    #[test]
    fn classify_matches_parse_line() {
        // classify() was pulled out of parse_line()'s own loop -- this
        // pins down that the refactor didn't change parse_line's actual
        // classification behavior.
        let line = "Failed password for root from 10.0.0.1 port 22 ssh2";
        let entry = parse_line(line).expect("should classify");
        let (severity, label) = classify(line);
        assert_eq!(format!("{:?}", entry.severity), format!("{:?}", severity));
        assert!(entry.message.starts_with(&format!("[{}]", label)));
    }

    #[test]
    fn known_labels_has_no_duplicates_and_is_nonempty() {
        let labels = known_labels();
        assert!(!labels.is_empty());
        let mut seen = std::collections::HashSet::new();
        for label in &labels {
            assert!(seen.insert(*label), "duplicate label: {}", label);
        }
    }
}
