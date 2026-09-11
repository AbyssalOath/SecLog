use seclog::parser;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::env;
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Seek, SeekFrom};
use std::time::Duration;
use tokio::task::JoinHandle;
use regex::Regex;
use std::sync::OnceLock;

#[cfg(target_os = "windows")]
use std::process::Command;

#[derive(Serialize)]
struct NewLogEntry {
    severity: String,
    user: String,
    message: String,
    host: String,
}

#[derive(Deserialize)]
struct AgentConfigResponse {
    hostname: String,
    paths: Vec<String>,
}

#[derive(Serialize)]
struct SelfRegisterRequest {
    enrollment_token: String,
    hostname: String,
}

#[derive(Deserialize)]
struct RegisterResponse {
    agent_id: i32,
    api_key: String,
}

const KEY_FILE: &str = ".seclog_agent_key";

fn load_saved_key() -> Option<String> {
    fs::read_to_string(KEY_FILE).ok().map(|s| s.trim().to_string())
}

fn save_key(key: &str) {
    if let Err(e) = fs::write(KEY_FILE, key) {
        eprintln!(
            "Warning: failed to save agent key to {}: {} -- this agent will try to \
             re-register with the same enrollment token next restart, which will fail \
             since it's single-use",
            KEY_FILE, e
        );
    }
}

// Every reqwest::Client in this file should come from here. The default
// client has no timeout at all, so a connection that stalls without ever
// closing (a dead NAT mapping, a proxy that swallows the response) would
// hang a watch loop indefinitely -- the retry logic in ship_line never
// even gets a chance to run since the single attempt in flight never
// returns.
fn new_http_client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .build()
        .unwrap_or_else(|_| reqwest::Client::new())
}

// Turns a filesystem path like "/var/log/auth.log" into a safe filename
// for storing that file's watch position, e.g.
// ".shipper_state__var_log_auth_log_3a7f...". We can't use the raw path as
// a filename since it contains '/'.
//
// The human-readable part alone isn't enough to be unique: every
// non-alphanumeric character (including a literal '_' already in the
// path) collapses to '_', so e.g. "/var/log/auth.log" and
// "/var/log/auth_log" would otherwise both map to
// ".shipper_state__var_log_auth_log" and silently share -- and corrupt --
// each other's read position. The hash suffix guarantees two different
// paths never collide, while the readable prefix stays for humans
// browsing the working directory.
fn state_file_for(path: &str) -> String {
    let safe: String = path
        .chars()
        .map(|c| if c.is_alphanumeric() { c } else { '_' })
        .collect();
    let hash = &parser::hash_line(path)[..16];
    format!(".shipper_state_{}_{}", safe, hash)
}

fn load_position(state_file: &str) -> Option<u64> {
    fs::read_to_string(state_file).ok().and_then(|s| s.trim().parse().ok())
}

fn save_position(state_file: &str, position: u64) {
    if let Err(e) = fs::write(state_file, position.to_string()) {
        eprintln!("Warning: failed to save position for {}: {}", state_file, e);
    }
}

// When a shipper runs under systemd, its stdout/stderr goes to the
// journal by default -- and on many distros (Fedora/RHEL included),
// rsyslog forwards journal entries straight into /var/log/messages and
// /var/log/secure. If those are also watched paths, the shipper ends up
// re-ingesting its OWN "Shipped: ..." output as a brand new log line,
// shipping THAT, producing another line to re-ingest, forever -- each
// generation slightly longer than the last. This is what actually fills
// a disk overnight, not organic log volume.
//
// Every systemd-launched process's journal lines are tagged
// "processname[pid]:" -- ours will always be "shipper[<pid>]:", so this
// is a reliable, general way to recognize and skip our own echoed output
// before it ever reaches ship_line, regardless of exact message wording.
fn looks_like_own_output(line: &str) -> bool {
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| Regex::new(r"\bshipper\[\d+\]:").unwrap());
    re.is_match(line)
}

async fn ship_line(client: &reqwest::Client, logs_url: &str, api_key: &str, host: &str, line: &str) -> bool {
    match parser::parse_line(line) {
        Some(entry) => {
            let payload = NewLogEntry {
                severity: format!("{:?}", entry.severity),
                user: entry.user,
                message: entry.message,
                host: host.to_string(),
            };

            const MAX_RETRIES: u32 = 3;
            for attempt in 1..=MAX_RETRIES {
                match client
                    .post(logs_url)
                    .header("X-Agent-Key", api_key)
                    .json(&payload)
                    .send()
                    .await
                {
                    // A response that actually arrived is only a delivery if
                    // the server returned 2xx. Treating any response (401
                    // from a revoked key, 400 from a rejected payload, a 5xx
                    // from the server) as "shipped" was the bug that made
                    // the shipper silently advance past -- and permanently
                    // drop -- every line once the server started rejecting
                    // requests, all while printing what looked like a normal
                    // "Shipped (...)" log.
                    Ok(response) if response.status().is_success() => {
                        // Deliberately NOT echoing the shipped line's content
                        // here. Printing the full line is exactly what feeds
                        // the journald->rsyslog->watched-file loop described
                        // above -- a status code alone gives you enough to
                        // confirm shipping is working via `journalctl`,
                        // without creating new content for anything to re-ingest.
                        println!("Shipped ({})", response.status());
                        return true;
                    }
                    Ok(response) => {
                        eprintln!(
                            "Attempt {}/{} failed to ship line: server returned {}",
                            attempt,
                            MAX_RETRIES,
                            response.status()
                        );
                        if attempt < MAX_RETRIES {
                            tokio::time::sleep(Duration::from_secs(2)).await;
                        }
                    }
                    Err(e) => {
                        eprintln!("Attempt {}/{} failed to ship line: {}", attempt, MAX_RETRIES, e);
                        if attempt < MAX_RETRIES {
                            tokio::time::sleep(Duration::from_secs(2)).await;
                        }
                    }
                }
            }
            false
        }
        None => {
            println!("SKIPPED (bad format, {} bytes)", line.len());
            true
        }
    }
}

// One independent, long-running watch loop per file. This function never
// returns on its own -- it only stops when its task is explicitly aborted
// by main() (when the path is removed from the agent's config).
async fn watch_file(path: String, logs_url: String, api_key: String, host: String) {
    println!("[{}] Starting watch", path);
    let state_file = state_file_for(&path);
    let client = new_http_client();

    // Outer loop: handles (re)opening the file, including recovering if
    // it's temporarily missing or becomes inaccessible mid-watch.
    'reconnect: loop {
        let mut file = match File::open(&path) {
            Ok(f) => f,
            Err(e) => {
                eprintln!("[{}] Could not open file: {} -- retrying in 5s", path, e);
                tokio::time::sleep(Duration::from_secs(5)).await;
                continue 'reconnect;
            }
        };

        let mut position = match load_position(&state_file) {
            Some(pos) => pos,
            None => file.seek(SeekFrom::End(0)).unwrap_or(0),
        };

        // Inner loop: normal polling for new lines, same idea as your
        // original shipper, just scoped per-file now.
        loop {
            let metadata = match fs::metadata(&path) {
                Ok(m) => m,
                Err(e) => {
                    eprintln!("[{}] Lost access to file: {} -- reconnecting", path, e);
                    continue 'reconnect;
                }
            };
            let size = metadata.len();

            // File got smaller than our saved position -- almost certainly
            // log rotation replaced it with a fresh, smaller file. Reset.
            if size < position {
                println!("[{}] File appears rotated/truncated, resetting", path);
                position = 0;
            }

            if size > position {
                if file.seek(SeekFrom::Start(position)).is_err() {
                    continue 'reconnect;
                }

                let mut reader = BufReader::new(&file);
                let mut raw = Vec::new();

                loop {
                    raw.clear();
                    let bytes_read = match reader.read_until(b'\n', &mut raw) {
                        Ok(n) => n as u64,
                        Err(_) => break,
                    };

                    if bytes_read == 0 {
                        // Genuine EOF -- nothing left to read this poll.
                        break;
                    }

                    // A chunk that doesn't end in '\n' is a line still being
                    // written (we polled mid-write). Ship it later, once it's
                    // complete -- ADVANCING PAST IT NOW would overshoot the
                    // real end of file (this exact bug used to make the
                    // "file appears rotated" check below fire falsely, and
                    // could chop the first byte(s) off whatever got appended
                    // next), so leave the read position where it is and wait
                    // for the next poll instead.
                    if !raw.ends_with(b"\n") {
                        break;
                    }

                    // Strip the newline, and a preceding '\r' too so
                    // CRLF-terminated files (e.g. logs copied over from
                    // Windows) parse the same as LF-only ones. bytes_read
                    // itself -- not the stripped string's length -- is what
                    // we advance position by, so the byte accounting stays
                    // exact regardless of line-ending style.
                    let mut content_len = raw.len();
                    if content_len > 0 && raw[content_len - 1] == b'\n' {
                        content_len -= 1;
                    }
                    if content_len > 0 && raw[content_len - 1] == b'\r' {
                        content_len -= 1;
                    }
                    let line = String::from_utf8_lossy(&raw[..content_len]).into_owned();

                    // See looks_like_own_output above -- this is the actual
                    // break in the feedback loop. We still advance/save the
                    // read position so these lines aren't retried forever,
                    // we just never ship or print their content.
                    if looks_like_own_output(&line) {
                        position += bytes_read;
                        save_position(&state_file, position);
                        continue;
                    }

                    if ship_line(&client, &logs_url, &api_key, &host, &line).await {
                        position += bytes_read;
                        save_position(&state_file, position);
                    } else {
                        break;
                    }
                }
            }

            tokio::time::sleep(Duration::from_millis(1000)).await;
        }
    }
}

// Maps well-known Windows Security event IDs to a severity + label,
// same spirit as the regex rule table used for Linux/macOS text logs.
#[cfg(target_os = "windows")]
fn classify_event_id(event_id: &str) -> (&'static str, &'static str) {
    match event_id {
        "4625" => ("High", "Failed logon"),
        "4648" => ("Medium", "Explicit credential logon"),
        "4672" => ("High", "Special privileges assigned (admin logon)"),
        "4720" => ("Medium", "User account created"),
        "4726" => ("Medium", "User account deleted"),
        "4732" => ("High", "User added to security-enabled group"),
        "4738" => ("Medium", "User account changed"),
        "4740" => ("High", "User account locked out"),
        "1102" => ("Critical", "Security audit log cleared"),
        _ => ("Low", "Windows security event"),
    }
}

// Polls the Windows Security event log periodically via wevtutil, a
// built-in Windows command-line tool -- no external crate needed, and
// it works the same way whether run interactively or as a service.
#[cfg(target_os = "windows")]
async fn watch_windows_security_log(logs_url: String, api_key: String, host: String) {
    println!("[WindowsEventLog] Starting watch on Security log");
    let client = new_http_client();

    loop {
        // /rd:true = most recent first, /c:20 = last 20 events, /f:text =
        // human-readable text output (easier to line-parse than XML here).
        let output = Command::new("wevtutil")
            .args(["qe", "Security", "/rd:true", "/c:20", "/f:text"])
            .output();

        match output {
            Ok(out) => {
                let text = String::from_utf8_lossy(&out.stdout);

                // wevtutil separates each event with a blank line; each
                // event's block contains an "Event ID:" line somewhere in it.
                for event_block in text.split("\r\n\r\n") {
                    if event_block.trim().is_empty() {
                        continue;
                    }

                    let event_id = event_block
                        .lines()
                        .find_map(|l| l.trim().strip_prefix("Event ID:"))
                        .map(|s| s.trim().to_string());

                    let Some(event_id) = event_id else { continue };
                    let (severity, label) = classify_event_id(&event_id);

                    // Reuse the same NewLogEntry shape and ship_line-style
                    // POST as the file-based path, just built directly here
                    // instead of going through parser::parse_line (Windows
                    // event text doesn't match the Linux/macOS line formats).
                    let payload = NewLogEntry {
                        severity: severity.to_string(),
                        user: "system".to_string(),
                        message: format!("[{}] EventID={} {}", label, event_id, event_block.trim()),
                        host: host.clone(),
                    };

                    match client
                        .post(&logs_url)
                        .header("X-Agent-Key", &api_key)
                        .json(&payload)
                        .send()
                        .await
                    {
                        Ok(resp) => println!("Shipped Windows event {} ({})", event_id, resp.status()),
                        Err(e) => eprintln!("Failed to ship Windows event: {}", e),
                    }
                }
            }
            Err(e) => {
                eprintln!("Failed to run wevtutil: {} (are you running as Administrator?)", e);
            }
        }

        tokio::time::sleep(Duration::from_secs(30)).await;
    }
}

#[cfg(target_os = "macos")]
async fn watch_macos_unified_log(logs_url: String, api_key: String, host: String) {
    use tokio::io::{AsyncBufReadExt, BufReader};
    use tokio::process::Command;

    println!("[macOS UnifiedLog] Starting watch");

    let mut child = match Command::new("log")
        .args(["stream", "--style", "syslog", "--predicate",
               "eventMessage contains \"authentication\" or eventMessage contains \"sudo\" or eventMessage contains \"failed\""])
        .stdout(std::process::Stdio::piped())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Failed to start `log stream`: {}", e);
            return;
        }
    };

    let stdout = match child.stdout.take() {
        Some(s) => s,
        None => return,
    };

    let mut reader = BufReader::new(stdout).lines();
    let client = new_http_client();

    // AsyncBufReadExt::lines gives us an async iterator -- each
    // .next_line().await yields control back to the runtime while
    // waiting for output, exactly like your file-watching loops do.
    while let Ok(Some(line)) = reader.next_line().await {
        ship_line(&client, &logs_url, &api_key, &host, &line).await;
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let base_url = env::var("SHIPPER_API_URL").unwrap_or_else(|_| "http://localhost:3000".to_string());
    let client = new_http_client();

    let api_key = if let Some(key) = load_saved_key() {
        println!("Using saved agent key from {}", KEY_FILE);
        key
    } else {
        // First run: use a one-time enrollment token to self-register,
        // auto-detecting this machine's hostname instead of requiring
        // an admin to type it in ahead of time.
        let enrollment_token = env::var("SECLOG_ENROLLMENT_TOKEN")
            .expect("First run requires SECLOG_ENROLLMENT_TOKEN (generate one from the admin UI)");

        let detected_hostname = hostname::get()
            .ok()
            .and_then(|h| h.into_string().ok())
            .unwrap_or_else(|| "unknown-host".to_string());

        let register_url = format!("{}/agents/self-register", base_url);
        let payload = SelfRegisterRequest { enrollment_token, hostname: detected_hostname.clone() };

        let resp = client.post(&register_url).json(&payload).send().await?;
        if !resp.status().is_success() {
            panic!("Self-registration failed: {}", resp.status());
        }
        let data: RegisterResponse = resp.json().await?;
        println!("Registered as agent id={} (hostname: {})", data.agent_id, detected_hostname);

        save_key(&data.api_key);
        data.api_key
    };

    let config_url = format!("{}/agents/config", base_url);
    let logs_url = format!("{}/logs", base_url);

    // Tracks which paths we're currently watching and the running task
    // for each one -- this is what lets us start/stop individual watchers
    // as the server's config changes, without restarting everything.
    let mut active: HashMap<String, JoinHandle<()>> = HashMap::new();

    // Fetch our registered hostname once at startup -- this is what gets
    // attached to every log line we ship, rather than trusting a locally
    // guessed value.
    let hostname = loop {
        match client.get(&config_url).header("X-Agent-Key", &api_key).send().await {
            Ok(resp) if resp.status().is_success() => {
                match resp.json::<AgentConfigResponse>().await {
                    Ok(cfg) => break cfg.hostname,
                    Err(e) => eprintln!("Failed to parse initial config: {}", e),
                }
            }
            Ok(resp) => eprintln!("Initial config fetch failed: {}", resp.status()),
            Err(e) => eprintln!("Cannot reach server: {}", e),
        }
        tokio::time::sleep(Duration::from_secs(5)).await;
    };
    println!("Registered as hostname: {}", hostname);

    println!("Seclog shipper starting -- polling config from {}", config_url);

    // On Windows, also watch the Security event log directly -- this runs
    // independently of any file-based watched_paths, since Windows security
    // events don't live in a flat text file at all.
    #[cfg(target_os = "windows")]
    {
        let logs_url_clone = logs_url.clone();
        let api_key_clone = api_key.clone();
        let host_clone = hostname.clone();
        tokio::spawn(async move {
            watch_windows_security_log(logs_url_clone, api_key_clone, host_clone).await;
        });
    }

    #[cfg(target_os = "macos")]
    {
        let logs_url_clone = logs_url.clone();
        let api_key_clone = api_key.clone();
        let host_clone = hostname.clone();
        tokio::spawn(async move {
            watch_macos_unified_log(logs_url_clone, api_key_clone, host_clone).await;
        });
    }

    loop {
        match client.get(&config_url).header("X-Agent-Key", &api_key).send().await {
            Ok(response) if response.status().is_success() => {
                match response.json::<AgentConfigResponse>().await {
                    Ok(config) => {
                        let desired: HashSet<String> = config.paths.into_iter().collect();

                        // Stop watching anything no longer in the desired set.
                        let to_remove: Vec<String> = active
                            .keys()
                            .filter(|p| !desired.contains(*p))
                            .cloned()
                            .collect();

                        for path in to_remove {
                            if let Some(handle) = active.remove(&path) {
                                handle.abort(); // forcibly stops that task
                                println!("Stopped watching: {}", path);
                            }
                        }

                        // Start watching anything new.
                        for path in desired {
                            if let std::collections::hash_map::Entry::Vacant(e) = active.entry(path) {
                                let p = e.key().clone();
                                let logs_url_clone = logs_url.clone();
                                let api_key_clone = api_key.clone();
                                let host_clone = hostname.clone();
                                let handle = tokio::spawn(async move {
                                    watch_file(p, logs_url_clone, api_key_clone, host_clone).await;
                                });
                                e.insert(handle);
                            }
                        }
                    }
                    Err(e) => eprintln!("Failed to parse config response: {}", e),
                }
            }
            Ok(response) => {
                eprintln!("Config fetch failed with status: {}", response.status());
            }
            Err(e) => {
                eprintln!("Failed to reach server for config: {}", e);
            }
        }

        // Wait before checking config again. Individual file watchers
        // keep running independently in the background during this wait --
        // this loop only handles reconciling the SET of watched files.
        tokio::time::sleep(Duration::from_secs(30)).await;
    }
}
