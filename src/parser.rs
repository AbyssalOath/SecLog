use crate::models::{LogEntry, Severity};
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
            Rule { pattern: Regex::new(r"(?=.*type=USER_LOGIN)(?=.*res=failed)").unwrap(), severity: Severity::Medium, label: "Failed login (audit)" },
            Rule { pattern: Regex::new(r"(?=.*type=USER_LOGIN)(?=.*res=success)").unwrap(), severity: Severity::Low, label: "Successful login (audit)" },
            Rule { pattern: Regex::new(r"(?=.*type=CRYPTO_KEY_USER)(?=.*res=success)").unwrap(), severity: Severity::Low, label: "SSH session key teardown (routine)" },
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
// associated user at all.
fn extract_user(line: &str) -> String {
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
        if let Some(caps) = re.captures(line) {
            if let Some(m) = caps.get(1) {
                return m.as_str().to_string();
            }
        }
    }

    "system".to_string()
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

    let mut severity = Severity::Low;
    let mut label = "Unclassified";

    for rule in rules() {
        if rule.pattern.is_match(line) {
            severity = rule.severity.clone();
            label = rule.label;
            break; // first match wins -- rules are checked in priority order
        }
    }

    // Prefix the detection label onto the stored message, so it's visible
    // in the dashboard without needing a whole new DB column right now.
    let message = format!("[{}] {}", label, line);

    Some(LogEntry { severity, user, message })
}

pub fn hash_line(line: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(line.as_bytes());
    let result = hasher.finalize();
    result.iter().map(|b| format!("{:02x}", b)).collect()
}
