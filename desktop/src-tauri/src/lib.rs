//! Envoir desktop — sidecar lifecycle + REAL-mode wiring.
//!
//! This Tauri v2 app bundles the Envoir static client (the `client/` frontend) and runs the real
//! `envoir-node` binary as a **managed sidecar**, so the whole node runs on the user's own machine.
//! The webview client then talks to it in REAL mode over the node's loopback JMAP surface
//! (spec §8.1), exactly as if the user had started `envoir-node run` by hand.
//!
//! ## What `run()` does
//! 1. Resolves a per-user app-data dir and a `node/` data dir under it.
//! 2. On first run, generates a random app-password (persisted, so the client keeps working across
//!    restarts) and — if there is no keystore yet — runs `envoir-node init` once to mint the
//!    identity keystore.
//! 3. Spawns `envoir-node run` as a Tauri sidecar with the node's real environment (loopback binds,
//!    JMAP on, the generated app-password, the Send API on with a generated admin token), draining
//!    its stdout/stderr to the log.
//! 4. Provisions the **send capability token** (spec §13.5.1) the client needs for real outbound
//!    send: reuses the persisted token from a previous launch if the node still honors it
//!    (`POST /v1/keys/verify`), otherwise mints a fresh scoped key (`POST /v1/keys`, admin-guarded)
//!    and persists it next to the app-password. Bounded retries, never fatal: on failure the token
//!    is simply omitted and the client keeps its honest "seam" send mode (`client/js/net/send.js`).
//! 5. Creates the main window with an initialization script that injects `window.__ENVOIR_NODE__`
//!    — the exact shape `client/js/store.js::resolveNodeConfig()` reads — so `js/net/sync.js`
//!    auto-connects in REAL mode, with real send, with no user configuration.
//! 6. Kills the sidecar on app exit (`RunEvent::Exit`).
//!
//! The node's JMAP listener is loopback-bound and app-password gated; a small CORS allowance on that
//! listener (see `node/src/jmap_api.rs`) lets the `tauri://` webview origin reach it. CORS is not the
//! security boundary there — the app-password is.

use std::collections::HashMap;
use std::path::Path;
use std::sync::Mutex;
use std::time::Duration;

use tauri::{Manager, RunEvent, WebviewUrl, WebviewWindowBuilder};
use tauri_plugin_shell::process::{CommandChild, CommandEvent};
use tauri_plugin_shell::ShellExt;

/// The loopback host:port the node's JMAP listener binds (spec §8.2 — plain HTTP only on loopback).
const JMAP_BIND: &str = "127.0.0.1:4700";
/// The base URL the client uses to reach the node's JMAP surface.
const JMAP_BASE_URL: &str = "http://127.0.0.1:4700";
/// The loopback host:port for the node's mesh transport (kept local for a desktop install).
const NODE_BIND: &str = "127.0.0.1:4600";
/// The loopback host:port for the node's Envoir Send API (spec §13.5.1).
const SEND_API_BIND: &str = "127.0.0.1:4610";
/// The JMAP app-password username. Must match the `username` injected into the webview and the
/// left side of `ENVOIR_JMAP_APP_PASSWORDS` (`<username>:<secret>`).
const APP_USER: &str = "envoir";
/// The sidecar program name passed to `ShellExt::sidecar`. `tauri-build` copies the configured
/// externalBin (`binaries/envoir-node-<target-triple>`, see `tauri.conf.json`) next to the app
/// executable with the triple stripped, so at runtime it is resolved by this **base name**.
const SIDECAR: &str = "envoir-node";
/// How many times to poll the just-spawned sidecar's Send API when provisioning the send token
/// (the listener binds within the daemon's first few hundred ms; each miss waits
/// [`SEND_TOKEN_RETRY_DELAY`]).
const SEND_TOKEN_ATTEMPTS: u32 = 25;
/// Pause between provisioning attempts: 25 × 200 ms ⇒ a ≤ 5 s *bounded* wait — provisioning may
/// delay first paint slightly on a slow first run, but can never hang startup.
const SEND_TOKEN_RETRY_DELAY: Duration = Duration::from_millis(200);
/// Per-request socket budget (connect + read + write) for the one-shot loopback HTTP calls.
const SEND_API_IO_TIMEOUT: Duration = Duration::from_secs(5);

/// Holds the running sidecar child so it can be killed on exit.
#[derive(Default)]
struct NodeProcess(Mutex<Option<CommandChild>>);

/// Entry point invoked from `main.rs`.
pub fn run() {
    let app = tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .manage(NodeProcess::default())
        .setup(|app| {
            let handle = app.handle().clone();
            if let Err(e) = start_node_and_window(&handle) {
                // Fail loudly: without the node the client would silently fall back to SIMULATION.
                eprintln!("envoir-desktop: fatal — could not start the local node: {e}");
                return Err(e);
            }
            Ok(())
        })
        .build(tauri::generate_context!())
        .expect("error while building the Envoir desktop app");

    app.run(|app_handle, event| {
        if let RunEvent::Exit = event {
            // Kill the managed node so it never outlives the app (no orphaned loopback listener).
            if let Some(child) = app_handle
                .state::<NodeProcess>()
                .0
                .lock()
                .expect("node process lock poisoned")
                .take()
            {
                let _ = child.kill();
            }
        }
    });
}

/// Resolve the data dir, ensure the identity keystore, spawn the node, and build the main window
/// with the injected REAL-mode config. Any failure is fatal (see `run()`).
fn start_node_and_window(app: &tauri::AppHandle) -> Result<(), Box<dyn std::error::Error>> {
    let app_data = app.path().app_data_dir()?;
    std::fs::create_dir_all(&app_data)?;
    let node_dir = app_data.join("node");
    std::fs::create_dir_all(&node_dir)?;

    // A stable per-install app-password + Send admin token (generated once, then reused).
    let app_password = load_or_create_secret(&app_data.join("app-password"))?;
    let send_admin_token = load_or_create_secret(&app_data.join("send-admin-token"))?;
    let env = node_env(&node_dir, &app_password, &send_admin_token);

    // First run: mint the identity keystore if absent. `envoir-node init` is idempotent (it refuses
    // to overwrite an existing keystore without ENVOIR_FORCE_INIT), so guarding on the file is just
    // to avoid a needless process spawn.
    let keystore = node_dir.join("keystore.json");
    if !keystore.exists() {
        run_node_init(app, &env)?;
    }

    // Spawn the long-lived daemon and keep the child so we can kill it on exit.
    let child = spawn_node_run(app, &env)?;
    app.state::<NodeProcess>()
        .0
        .lock()
        .expect("node process lock poisoned")
        .replace(child);

    // Provision the send capability token (spec §13.5.1) against the just-spawned daemon: reuse the
    // persisted one when the node still honors it, else mint via the admin-guarded POST /v1/keys.
    // Fail-safe by design — `None` just omits `sendToken` from the injected config, so the client
    // stays in its honest seam send mode; a provisioning failure never blocks app startup.
    let send_token = provision_send_token(&app_data, &send_admin_token);
    if send_token.is_none() {
        eprintln!(
            "envoir-desktop: no send token provisioned — real outbound send disabled, \
             the client stays in its honest seam send mode"
        );
    }

    // Inject the node config the client reads (store.js::resolveNodeConfig). serde_json renders a
    // valid JS object literal (and escapes the secrets safely).
    let node_cfg = node_config_json(&app_password, send_token.as_deref());
    let init_script = format!("window.__ENVOIR_NODE__ = {node_cfg};");

    WebviewWindowBuilder::new(app, "main", WebviewUrl::App("index.html".into()))
        .title("Envoir")
        .inner_size(1240.0, 840.0)
        .min_inner_size(880.0, 600.0)
        .initialization_script(&init_script)
        .build()?;

    Ok(())
}

/// The node's real runtime environment (spec `dmtap::config`): loopback binds, JMAP + Send API on,
/// the generated app-password, and the app-data node dir. Loopback-only — nothing is exposed off the
/// machine.
fn node_env(node_dir: &Path, app_password: &str, send_admin_token: &str) -> HashMap<String, String> {
    let mut env = HashMap::new();
    env.insert("ENVOIR_DATA_DIR".into(), node_dir.to_string_lossy().into_owned());
    env.insert("ENVOIR_NODE_BIND".into(), NODE_BIND.into());
    // Native JMAP client surface (spec §8.1) — the client's only sync path.
    env.insert("ENVOIR_JMAP".into(), "1".into());
    env.insert("ENVOIR_JMAP_BIND".into(), JMAP_BIND.into());
    env.insert("ENVOIR_JMAP_APP_PASSWORDS".into(), format!("{APP_USER}:{app_password}"));
    // Envoir Send API (spec §13.5.1) — enabled on loopback, with key-management unlocked by a
    // generated admin token (fail-closed without one).
    env.insert("ENVOIR_SEND_API".into(), "1".into());
    env.insert("ENVOIR_SEND_API_BIND".into(), SEND_API_BIND.into());
    env.insert("ENVOIR_SEND_ADMIN_TOKEN".into(), send_admin_token.into());
    env
}

/// The `window.__ENVOIR_NODE__` object the client reads (`store.js::resolveNodeConfig`):
/// `{ enabled, baseUrl, username, appPassword }` plus `sendToken` only when one was actually
/// provisioned. An *absent* key — not a placeholder — is what keeps `client/js/net/send.js` in its
/// honest seam mode: the client never gets a token that would 401 on every real send.
fn node_config_json(app_password: &str, send_token: Option<&str>) -> serde_json::Value {
    let mut cfg = serde_json::json!({
        "enabled": true,
        "baseUrl": JMAP_BASE_URL,
        "username": APP_USER,
        "appPassword": app_password,
    });
    if let Some(tok) = send_token {
        cfg["sendToken"] = serde_json::Value::String(tok.to_string());
    }
    cfg
}

/// Obtain the send capability token (spec §13.5.1) that authorizes the client's `POST /v1/send`.
///
/// Order of preference, polled for up to [`SEND_TOKEN_ATTEMPTS`] × [`SEND_TOKEN_RETRY_DELAY`]
/// while the just-spawned daemon's Send API comes up:
/// 1. **Reuse** the token persisted by a previous launch — but only after the node confirms it is
///    still honored (`POST /v1/keys/verify`). The node's send-key store is memory-backed today, so
///    a persisted secret is dead after every node restart; injecting it unverified would turn each
///    send into a `401` instead of the client's honest no-token seam mode. Ask, don't assume.
/// 2. **Mint** a fresh account-scoped prod key (`POST /v1/keys`, node-side default 1-year TTL) and
///    persist it next to the app-password (0600) so the next launch can attempt reuse.
///
/// Every failure path — API never comes up, admin routes disabled, malformed response — logs and
/// returns `None` (⇒ seam mode). Startup is delayed at most by the bounded retry budget, never
/// blocked indefinitely.
fn provision_send_token(app_data: &Path, admin_token: &str) -> Option<String> {
    let token_path = app_data.join("send-token");
    let persisted = std::fs::read_to_string(&token_path)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());

    for attempt in 0..SEND_TOKEN_ATTEMPTS {
        if attempt > 0 {
            std::thread::sleep(SEND_TOKEN_RETRY_DELAY);
        }
        // Reuse path: a definitive `valid:false` falls through to minting a replacement in this same
        // attempt; a transport error means the API is not up yet, so retry the whole attempt.
        if let Some(tok) = &persisted {
            match send_api_post("/v1/keys/verify", admin_token, &serde_json::json!({ "secret": tok })) {
                Ok((200, v)) if v["valid"] == true => return Some(tok.clone()),
                Ok((200, _)) => {} // node no longer honors it (e.g. restarted) → mint below
                Ok((status @ (401 | 403), v)) => {
                    // The admin gate itself refused — minting would fail identically, so stop here.
                    eprintln!("envoir-desktop: send-token verify refused (HTTP {status}): {v}");
                    return None;
                }
                // Any other status (e.g. a 404 from an older sidecar without /v1/keys/verify): the
                // probe is inconclusive but the mint route may still work — fall through and mint.
                Ok((_, _)) => {}
                Err(_) => continue,
            }
        }
        match send_api_post("/v1/keys", admin_token, &serde_json::json!({ "env": "prod" })) {
            Ok((200, v)) => {
                let Some(secret) = v["secret"].as_str() else {
                    eprintln!("envoir-desktop: /v1/keys returned 200 without a secret: {v}");
                    return None;
                };
                // Persist for the next launch's reuse attempt; a write failure is not fatal — the
                // in-memory token still serves this run.
                match std::fs::write(&token_path, secret) {
                    Ok(()) => restrict_permissions(&token_path),
                    Err(e) => eprintln!("envoir-desktop: could not persist the send token: {e}"),
                }
                return Some(secret.to_string());
            }
            Ok((status, v)) => {
                eprintln!("envoir-desktop: send-token mint refused (HTTP {status}): {v}");
                return None;
            }
            Err(_) => continue,
        }
    }
    eprintln!("envoir-desktop: Send API on {SEND_API_BIND} did not answer within the retry budget");
    None
}

/// One-shot loopback HTTP/1.1 POST to the sidecar's Send API, hand-rolled over `std::net` — the
/// same framework-free plumbing the node's own listeners use (`node/src/send_api.rs`); no HTTP
/// client dependency for two loopback calls. Returns `(status, parsed JSON body)`; a non-JSON body
/// parses as `Null` (the status still tells the caller what happened).
fn send_api_post(
    path: &str,
    admin_token: &str,
    body: &serde_json::Value,
) -> std::io::Result<(u16, serde_json::Value)> {
    use std::io::{Read as _, Write as _};
    let addr: std::net::SocketAddr = SEND_API_BIND
        .parse()
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, format!("bad bind: {e}")))?;
    let mut stream = std::net::TcpStream::connect_timeout(&addr, SEND_API_IO_TIMEOUT)?;
    stream.set_read_timeout(Some(SEND_API_IO_TIMEOUT))?;
    stream.set_write_timeout(Some(SEND_API_IO_TIMEOUT))?;
    let payload = serde_json::to_vec(body)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    stream.write_all(&http_post_request(path, admin_token, &payload))?;
    // `Connection: close` on the request ⇒ the node closes after one response, so EOF frames it.
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw)?;
    let (status, resp_body) = parse_http_response(&raw)
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "malformed HTTP response"))?;
    Ok((status, serde_json::from_slice(&resp_body).unwrap_or(serde_json::Value::Null)))
}

/// Build the raw HTTP/1.1 request bytes for an admin-guarded Send-API POST: admin Bearer token,
/// JSON body, and `Connection: close` so the response is EOF-delimited (no chunked/keep-alive
/// parsing needed on our side).
fn http_post_request(path: &str, bearer: &str, body: &[u8]) -> Vec<u8> {
    let head = format!(
        "POST {path} HTTP/1.1\r\nHost: {SEND_API_BIND}\r\nAuthorization: Bearer {bearer}\r\n\
         Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let mut out = head.into_bytes();
    out.extend_from_slice(body);
    out
}

/// Parse a raw HTTP/1.1 response into `(status, body)`. Only the status line matters here — the
/// request asked for `Connection: close`, so everything past the header terminator is the body.
fn parse_http_response(raw: &[u8]) -> Option<(u16, Vec<u8>)> {
    let header_end = raw.windows(4).position(|w| w == b"\r\n\r\n")?;
    let head = std::str::from_utf8(&raw[..header_end]).ok()?;
    let status_line = head.split("\r\n").next()?;
    let mut parts = status_line.split_whitespace();
    if !parts.next()?.starts_with("HTTP/1.") {
        return None;
    }
    let status: u16 = parts.next()?.parse().ok()?;
    Some((status, raw[header_end + 4..].to_vec()))
}

/// Run `envoir-node init` once and wait for it to finish, draining its output to the log.
fn run_node_init(
    app: &tauri::AppHandle,
    env: &HashMap<String, String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let cmd = app.shell().sidecar(SIDECAR)?.args(["init"]).envs(env.clone());
    let (mut rx, _child) = cmd.spawn()?;
    // Block until the init process terminates (setup() is synchronous; this is a one-shot).
    tauri::async_runtime::block_on(async {
        while let Some(event) = rx.recv().await {
            match event {
                CommandEvent::Stdout(line) | CommandEvent::Stderr(line) => {
                    log_node("init", &line);
                }
                CommandEvent::Terminated(_) => break,
                _ => {}
            }
        }
    });
    Ok(())
}

/// Spawn `envoir-node run` as the managed daemon, draining stdout/stderr to the log on a task.
fn spawn_node_run(
    app: &tauri::AppHandle,
    env: &HashMap<String, String>,
) -> Result<CommandChild, Box<dyn std::error::Error>> {
    let cmd = app.shell().sidecar(SIDECAR)?.args(["run"]).envs(env.clone());
    let (mut rx, child) = cmd.spawn()?;
    tauri::async_runtime::spawn(async move {
        while let Some(event) = rx.recv().await {
            match event {
                CommandEvent::Stdout(line) | CommandEvent::Stderr(line) => log_node("run", &line),
                CommandEvent::Terminated(payload) => {
                    eprintln!("[envoir-node/run] terminated: {payload:?}");
                    break;
                }
                _ => {}
            }
        }
    });
    Ok(child)
}

/// Log one line of node output (bytes → lossy UTF-8).
fn log_node(phase: &str, line: &[u8]) {
    let text = String::from_utf8_lossy(line);
    let text = text.trim_end();
    if !text.is_empty() {
        eprintln!("[envoir-node/{phase}] {text}");
    }
}

/// Load a persisted secret from `path`, or generate a fresh 32-byte CSPRNG secret (base64url,
/// unpadded), persist it (0600 on unix), and return it. Reused across restarts so the client's
/// injected credentials stay stable.
fn load_or_create_secret(path: &Path) -> Result<String, Box<dyn std::error::Error>> {
    if let Ok(existing) = std::fs::read_to_string(path) {
        let trimmed = existing.trim();
        if !trimmed.is_empty() {
            return Ok(trimmed.to_string());
        }
    }
    let secret = random_secret();
    std::fs::write(path, &secret)?;
    restrict_permissions(path);
    Ok(secret)
}

/// 32 random bytes from the OS CSPRNG, base64url-encoded without padding (URL/JS/Basic-auth safe).
fn random_secret() -> String {
    let mut bytes = [0u8; 32];
    getrandom::getrandom(&mut bytes).expect("OS CSPRNG unavailable");
    base64url_nopad(&bytes)
}

/// Minimal unpadded base64url encoder (RFC 4648 §5) — avoids pulling in a base64 crate for one call.
fn base64url_nopad(input: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity((input.len() * 4).div_ceil(3));
    for chunk in input.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(ALPHABET[((n >> 18) & 0x3f) as usize] as char);
        out.push(ALPHABET[((n >> 12) & 0x3f) as usize] as char);
        if chunk.len() > 1 {
            out.push(ALPHABET[((n >> 6) & 0x3f) as usize] as char);
        }
        if chunk.len() > 2 {
            out.push(ALPHABET[(n & 0x3f) as usize] as char);
        }
    }
    out
}

/// Best-effort tighten of a secret file to owner-only (0600) on unix; a no-op elsewhere.
fn restrict_permissions(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = std::fs::metadata(path) {
            let mut perms = meta.permissions();
            perms.set_mode(0o600);
            let _ = std::fs::set_permissions(path, perms);
        }
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64url_matches_known_vectors() {
        // RFC 4648 test vectors, unpadded base64url.
        assert_eq!(base64url_nopad(b""), "");
        assert_eq!(base64url_nopad(b"f"), "Zg");
        assert_eq!(base64url_nopad(b"fo"), "Zm8");
        assert_eq!(base64url_nopad(b"foo"), "Zm9v");
        assert_eq!(base64url_nopad(b"foob"), "Zm9vYg");
        assert_eq!(base64url_nopad(b"fooba"), "Zm9vYmE");
        assert_eq!(base64url_nopad(b"foobar"), "Zm9vYmFy");
    }

    #[test]
    fn random_secret_is_urlsafe_and_long() {
        let s = random_secret();
        // 32 bytes → 43 unpadded base64url chars.
        assert_eq!(s.len(), 43);
        assert!(s.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'));
        // Two draws differ (CSPRNG, not a constant).
        assert_ne!(s, random_secret());
    }

    #[test]
    fn node_env_has_loopback_binds_and_app_password() {
        let env = node_env(Path::new("/tmp/nd"), "sekret", "admintok");
        assert_eq!(env["ENVOIR_JMAP"], "1");
        assert_eq!(env["ENVOIR_JMAP_BIND"], "127.0.0.1:4700");
        assert_eq!(env["ENVOIR_JMAP_APP_PASSWORDS"], "envoir:sekret");
        assert_eq!(env["ENVOIR_DATA_DIR"], "/tmp/nd");
        assert_eq!(env["ENVOIR_SEND_API"], "1");
        assert_eq!(env["ENVOIR_SEND_ADMIN_TOKEN"], "admintok");
        // Every bind is loopback — nothing exposed off the machine.
        assert!(env["ENVOIR_NODE_BIND"].starts_with("127.0.0.1"));
        assert!(env["ENVOIR_SEND_API_BIND"].starts_with("127.0.0.1"));
    }

    #[test]
    fn injected_config_carries_send_token_only_when_provisioned() {
        // With a provisioned token: the full REAL-mode shape store.js::resolveNodeConfig reads.
        let with = node_config_json("pw", Some("envoir_live_abc"));
        assert_eq!(with["enabled"], true);
        assert_eq!(with["baseUrl"], "http://127.0.0.1:4700");
        assert_eq!(with["username"], "envoir");
        assert_eq!(with["appPassword"], "pw");
        assert_eq!(with["sendToken"], "envoir_live_abc");

        // Without: the KEY is absent (not empty/placeholder) — that's what keeps the client's
        // net/send.js in its honest seam mode instead of 401-ing on a dead token.
        let without = node_config_json("pw", None);
        assert!(without.get("sendToken").is_none());
        assert_eq!(without["appPassword"], "pw");
    }

    #[test]
    fn injected_config_renders_as_a_safe_js_object_literal() {
        // The init script embeds the JSON directly; serde_json must escape hostile secret bytes so
        // they can never break out of the string literal into script context.
        let cfg = node_config_json("p\"w</script>", Some("t'ok\\en"));
        let rendered = format!("window.__ENVOIR_NODE__ = {cfg};");
        assert!(!rendered.contains("p\"w"), "quote must be escaped: {rendered}");
        let round: serde_json::Value =
            serde_json::from_str(rendered.trim_start_matches("window.__ENVOIR_NODE__ = ").trim_end_matches(';'))
                .unwrap();
        assert_eq!(round["appPassword"], "p\"w</script>");
        assert_eq!(round["sendToken"], "t'ok\\en");
    }

    #[test]
    fn http_post_request_is_wellformed() {
        let req = http_post_request("/v1/keys", "admintok", b"{\"env\":\"prod\"}");
        let text = String::from_utf8(req).unwrap();
        assert!(text.starts_with("POST /v1/keys HTTP/1.1\r\n"));
        assert!(text.contains("\r\nHost: 127.0.0.1:4610\r\n"));
        assert!(text.contains("\r\nAuthorization: Bearer admintok\r\n"));
        assert!(text.contains("\r\nContent-Length: 14\r\n"));
        // Connection: close is load-bearing: send_api_post frames the response by EOF.
        assert!(text.contains("\r\nConnection: close\r\n"));
        assert!(text.ends_with("\r\n\r\n{\"env\":\"prod\"}"));
    }

    #[test]
    fn parse_http_response_extracts_status_and_body() {
        let ok = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{\"secret\":\"s\"}";
        assert_eq!(parse_http_response(ok), Some((200, b"{\"secret\":\"s\"}".to_vec())));
        // Status without a body (the admin-refused case still carries its code).
        assert_eq!(parse_http_response(b"HTTP/1.1 403 Forbidden\r\n\r\n").unwrap().0, 403);
        // Malformed responses are None, never a bogus (status, body).
        assert!(parse_http_response(b"no header terminator here").is_none());
        assert!(parse_http_response(b"SMTP 220 hi\r\n\r\n").is_none());
        assert!(parse_http_response(b"HTTP/1.1 notanumber OK\r\n\r\n").is_none());
    }
}
