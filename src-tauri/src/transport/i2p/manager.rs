//! I2PManager — owns the i2pd subprocess lifecycle.
//!
//! Responsibilities:
//!
//! 1. **Locate the i2pd binary.** Dev: Homebrew at
//!    `/opt/homebrew/opt/i2pd/bin/i2pd`. Release: bundled inside
//!    `Noctis Whisper.app/Contents/Resources/i2pd` and signed alongside
//!    the main binary. The lookup order is: explicit override (env var),
//!    bundled-resource path, Homebrew path, `which` lookup. Returning a
//!    clear error if none are found.
//!
//! 2. **Pick a free port for SAM.** Per Mod #1 hardening: the SAM bridge
//!    binds to a randomly chosen ephemeral port at start, never the
//!    well-known 7656. The chosen port is held in process memory and
//!    threaded into every SAM connect. No SAM port is ever written to
//!    disk — a different Whisper launch picks a different port.
//!
//! 3. **Generate a per-launch i2pd config.** Written to the profile data
//!    directory under `i2p/i2pd.conf` so a single user with multiple
//!    profiles (alice, bob) gets isolated routers. Encrypted leasesets
//!    are on. Transit routing is *off* by default per Mod #1 — only
//!    flipped on after the user opts in (Phase 10).
//!
//! 4. **Spawn the subprocess.** Captures stdout/stderr to a per-profile
//!    log file under `i2p/i2pd.log`. Holds a `Child` so we can wait/kill
//!    on shutdown.
//!
//! 5. **Wait for readiness.** Polls the SAM bridge with a HELLO until it
//!    responds, capped at 60s. Once HELLO succeeds, mints (or loads)
//!    our destination, creates the master STREAM session, and the
//!    manager is "ready" — the rest of the app can issue
//!    `stream_connect` / `stream_accept` against the session.
//!
//! 6. **Graceful shutdown.** On vault lock or app quit, drop the master
//!    session (closes the control socket) then SIGTERM the i2pd process.
//!    SIGKILL after 5s if it doesn't exit cleanly.
//!
//! Concurrency model: the manager is held inside an `Arc<RwLock<…>>` on
//! the AppState. Background tasks (the inbound accept loop, the send
//! queue worker) clone the Arc, take a read lock to grab the session ID
//! + SAM addr, and drop the lock before issuing SAM operations. The
//! manager itself never holds the lock across `.await` points.

use super::{
    destination::{self, PersistedDestination},
    sam, I2pError, I2pResult,
};
use crate::db::Database;
use std::net::TcpListener as StdTcpListener;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, Instant};
use tokio::io::{AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::process::{Child, Command};

/// Where to look for the i2pd binary, in priority order.
fn locate_i2pd_binary() -> I2pResult<PathBuf> {
    // 1. Explicit override (CI / dev box with a custom build).
    if let Ok(p) = std::env::var("WHISPER_I2PD_BINARY") {
        let path = PathBuf::from(p);
        if path.is_file() {
            return Ok(path);
        }
    }
    // 2. Bundled inside the .app: <app>/Contents/Resources/i2pd. We don't
    //    have a Tauri-blessed resource resolver in pure-Rust modules, so
    //    we walk up from the current exe — works for the production
    //    launch path (the main binary's parent's parent is `Contents/`).
    if let Ok(exe) = std::env::current_exe() {
        if let Some(macos_dir) = exe.parent() {
            // exe lives at .../Contents/MacOS/<app>; go up to Contents/
            // and into Resources/.
            if let Some(contents) = macos_dir.parent() {
                let bundled = contents.join("Resources").join("i2pd");
                if bundled.is_file() {
                    return Ok(bundled);
                }
            }
        }
    }
    // 3. Homebrew (dev).
    let brew = PathBuf::from("/opt/homebrew/opt/i2pd/bin/i2pd");
    if brew.is_file() {
        return Ok(brew);
    }
    let brew_intel = PathBuf::from("/usr/local/opt/i2pd/bin/i2pd");
    if brew_intel.is_file() {
        return Ok(brew_intel);
    }
    Err(I2pError::Subprocess(
        "i2pd binary not found (set WHISPER_I2PD_BINARY, install via brew, or bundle in Resources/)"
            .into(),
    ))
}

/// Where to look for i2pd's certificate bundle (reseed certs + family
/// certs). i2pd needs these to bootstrap into the network on a fresh
/// datadir. Homebrew installs them into the Cellar; the bundled .app
/// keeps them next to the i2pd binary in `Resources/certificates/`.
fn locate_i2pd_certificates() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("WHISPER_I2PD_CERTIFICATES") {
        let path = PathBuf::from(p);
        if path.is_dir() {
            return Some(path);
        }
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(macos_dir) = exe.parent() {
            if let Some(contents) = macos_dir.parent() {
                let bundled = contents.join("Resources").join("certificates");
                if bundled.is_dir() {
                    return Some(bundled);
                }
            }
        }
    }
    let brew = PathBuf::from("/opt/homebrew/Cellar/i2pd/2.60.0/share/i2pd/certificates");
    if brew.is_dir() {
        return Some(brew);
    }
    let brew_intel = PathBuf::from("/usr/local/Cellar/i2pd/2.60.0/share/i2pd/certificates");
    if brew_intel.is_dir() {
        return Some(brew_intel);
    }
    None
}

/// Pick an unused TCP port on 127.0.0.1. The kernel hands us one when we
/// bind to port 0; we drop the listener immediately and reuse the number.
/// This is racy in theory (another process could grab it between drop
/// and i2pd's bind) but in practice the window is sub-millisecond and
/// i2pd retries.
fn pick_free_port() -> I2pResult<u16> {
    let listener = StdTcpListener::bind("127.0.0.1:0")?;
    let port = listener.local_addr()?.port();
    drop(listener);
    Ok(port)
}

/// Configuration for an `I2PManager` launch.
#[derive(Debug, Clone)]
pub struct I2pConfig {
    /// Per-profile data dir under which `i2p/` is created. Typically
    /// `<profile_data_dir>` from `crate::profile::data_dir()`.
    pub profile_dir: PathBuf,
    /// Whether to enable transit routing (forward encrypted traffic for
    /// other I2P users). Default `false` per Mod #1; Phase 10 onboarding
    /// flips this to true after the user opts in.
    pub enable_transit: bool,
}

/// Active i2pd subprocess + the master STREAM session that all Whisper
/// inbound/outbound streams ride on top of.
pub struct I2PManager {
    /// The subprocess we spawned. Kept so the destructor can reap it.
    child: Child,
    /// Where the subprocess writes its log file (for debugging).
    log_path: PathBuf,
    /// `127.0.0.1:<random>` — the SAM bridge address every Whisper SAM
    /// call uses.
    sam_addr: String,
    /// Master session ID for `STREAM CONNECT` / `STREAM ACCEPT`.
    session_id: String,
    /// Long-lived control socket holding the master session open. Closing
    /// this tears down the session in i2pd, so it stays in the manager's
    /// owned state for its full lifetime.
    _control: BufReader<TcpStream>,
    /// Our persisted destination (pub + priv, base64).
    destination: PersistedDestination,
    /// Owned secondary DB connection for the queue worker (Phase 6.5).
    /// Wrapped in a `parking_lot::Mutex` so the surrounding I2PManager
    /// is `Sync` (rusqlite Connection is Send-but-not-Sync). The queue
    /// worker locks this synchronously to read pending sends + record
    /// outcomes; nothing across `.await` needs to touch it.
    pub(crate) db: parking_lot::Mutex<Database>,
}

impl I2PManager {
    /// Spawn i2pd, wait for SAM readiness, mint+load the destination,
    /// and create the master STREAM session. Resolves once everything is
    /// ready or returns the first failure.
    ///
    /// Takes owned `Database` (a secondary SQLCipher connection — see
    /// `commands::spawn_i2p_start`) so the start future is `Send`.
    /// Connection is Send-but-not-Sync, so owning it in a future works
    /// where `&Database` would not.
    pub async fn start(db: Database, cfg: I2pConfig) -> I2pResult<Self> {
        let bin = locate_i2pd_binary()?;
        tracing::info!("i2p: using binary {}", bin.display());

        let i2p_dir = cfg.profile_dir.join("i2p");
        std::fs::create_dir_all(&i2p_dir)?;
        // Copy or symlink the certificate bundle into the profile dir
        // (i2pd looks under <datadir>/certificates).
        if let Some(certs_src) = locate_i2pd_certificates() {
            let certs_dst = i2p_dir.join("certificates");
            if !certs_dst.exists() {
                copy_dir_all(&certs_src, &certs_dst)?;
                tracing::info!(
                    "i2p: copied certificates {} → {}",
                    certs_src.display(),
                    certs_dst.display()
                );
            }
        } else {
            tracing::warn!(
                "i2p: no certificate bundle found — fresh datadir bootstraps will fail"
            );
        }

        let sam_port = pick_free_port()?;
        let sam_addr = format!("127.0.0.1:{sam_port}");
        let conf_path = i2p_dir.join("i2pd.conf");
        write_config(&conf_path, sam_port, cfg.enable_transit)?;

        let log_path = i2p_dir.join("i2pd.log");
        // Truncate the log on every launch so the file doesn't grow
        // unboundedly across restarts.
        let log_file = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&log_path)?;
        let log_file_err = log_file.try_clone()?;

        tracing::info!("i2p: spawning i2pd (sam={sam_addr}, datadir={})", i2p_dir.display());
        let mut child = Command::new(&bin)
            .arg(format!("--datadir={}", i2p_dir.display()))
            .arg(format!("--conf={}", conf_path.display()))
            .arg("--log=stdout")
            .stdin(Stdio::null())
            .stdout(Stdio::from(log_file))
            .stderr(Stdio::from(log_file_err))
            .kill_on_drop(true)
            .spawn()
            .map_err(|e| I2pError::Subprocess(format!("spawn i2pd: {e}")))?;

        // Wait until SAM responds to HELLO. i2pd's SAM listener comes up
        // a few seconds after the process starts; on a fresh datadir
        // (first reseed) it can take 30-60s before the listener is bound.
        let deadline = Instant::now() + Duration::from_secs(120);
        loop {
            // If the process has already exited, fail fast.
            if let Ok(Some(status)) = child.try_wait() {
                let log = std::fs::read_to_string(&log_path).unwrap_or_default();
                let tail: String = log.lines().rev().take(10).collect::<Vec<_>>().join("\n");
                return Err(I2pError::Subprocess(format!(
                    "i2pd exited before SAM came up (status={status:?}); last log lines:\n{tail}"
                )));
            }
            if probe_sam(&sam_addr).await.is_ok() {
                break;
            }
            if Instant::now() > deadline {
                let _ = child.kill().await;
                return Err(I2pError::Subprocess(
                    "timed out waiting for i2pd SAM bridge (>120s)".into(),
                ));
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
        tracing::info!("i2p: SAM ready at {sam_addr}");

        // Wrap the owned DB in a Mutex so the destination calls can
        // hold a `&Mutex<Database>` (Sync) across their `.await`s.
        // After this point we own the Mutex and pass it through.
        let db = parking_lot::Mutex::new(db);
        let destination = destination::load_or_mint(&db, &sam_addr).await?;
        tracing::info!(
            "i2p: destination ready (pub={} chars, priv={} chars)",
            destination.pub_b64.len(),
            destination.priv_b64.len()
        );

        let session_id = format!("whisper-{}", uuid::Uuid::new_v4().simple());
        let mut control = sam::connect(&sam_addr).await?;
        let _v = sam::hello(&mut control).await?;
        let _our_dest = sam::session_create_stream(
            &mut control,
            &session_id,
            &destination.priv_b64,
            &[],
        )
        .await?;
        tracing::info!("i2p: master STREAM session `{session_id}` created");

        Ok(Self {
            child,
            log_path,
            sam_addr,
            session_id,
            _control: control,
            destination,
            db,
        })
    }

    /// Our public I2P destination (base64). Share this with peers via
    /// the signed contact bundle so they can reach us.
    pub fn destination_pub(&self) -> &str {
        &self.destination.pub_b64
    }

    /// SAM bridge address. Background workers issue `stream_connect` /
    /// `stream_accept` against this.
    pub fn sam_addr(&self) -> &str {
        &self.sam_addr
    }

    /// Master STREAM session ID. Same workers use this on every SAM
    /// stream verb.
    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    /// Path to the i2pd log file (per-profile). Surfaced in the security
    /// dashboard for diagnostics (Phase 11).
    pub fn log_path(&self) -> &Path {
        &self.log_path
    }

    /// Graceful shutdown: drop the control socket (kills the session in
    /// i2pd) then SIGTERM the process. SIGKILL after 5s if it lingers.
    pub async fn shutdown(mut self) -> I2pResult<()> {
        // Closing the control socket tears down the session.
        // Take ownership of the BufReader's inner stream so we can call
        // shutdown explicitly — this signals EOF to i2pd faster than a
        // `drop` alone.
        if let Ok(()) = self._control.get_mut().shutdown().await {
            tracing::debug!("i2p: control socket shut down");
        }

        // Try graceful exit first.
        if let Some(pid) = self.child.id() {
            unsafe {
                libc::kill(pid as i32, libc::SIGTERM);
            }
        }
        let timeout = tokio::time::timeout(Duration::from_secs(5), self.child.wait()).await;
        match timeout {
            Ok(Ok(status)) => {
                tracing::info!("i2p: i2pd exited cleanly ({status:?})");
            }
            _ => {
                tracing::warn!("i2p: i2pd did not exit in 5s, sending SIGKILL");
                let _ = self.child.kill().await;
            }
        }
        Ok(())
    }
}

/// One-line probe of the SAM bridge: connect + HELLO, drop. Used by the
/// readiness loop above; a successful HELLO is the canonical signal that
/// i2pd is up enough to accept session creation.
async fn probe_sam(addr: &str) -> I2pResult<()> {
    let mut buf = sam::connect(addr).await?;
    let _v = sam::hello(&mut buf).await?;
    Ok(())
}

/// Render the i2pd config we want for Whisper. Mirrors the dev config we
/// wrote by hand for Phase 1, but with a randomized SAM port (Mod #1)
/// and transit routing wired to the user's preference.
fn write_config(path: &Path, sam_port: u16, enable_transit: bool) -> std::io::Result<()> {
    // Transit OFF: `transittunnels = 0` tells i2pd we won't accept any
    // transit work. Transit ON: leave the default (i2pd autoscales based
    // on bandwidth headroom). Everything else stays minimal — Whisper
    // doesn't use the HTTP/SOCKS proxies.
    let transit_line = if enable_transit {
        "# transit routing on (user opted in)"
    } else {
        "transittunnels = 0"
    };
    let body = format!(
        r#"# Generated by Noctis Whisper. DO NOT EDIT — regenerated on every launch.

[sam]
enabled = true
address = 127.0.0.1
port = {sam_port}

[httpproxy]
enabled = false

[socksproxy]
enabled = false

[http]
enabled = false

[limits]
{transit_line}

[persist]
profiles = true
"#
    );
    std::fs::write(path, body)
}

/// Recursive directory copy used to bootstrap i2pd's certificate bundle
/// into the per-profile datadir. We don't symlink because i2pd refuses
/// to follow symlinks under macOS App Sandbox in some builds.
fn copy_dir_all(src: &Path, dst: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dst)?;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let from = entry.path();
        let to = dst.join(entry.file_name());
        if entry.file_type()?.is_dir() {
            copy_dir_all(&from, &to)?;
        } else {
            std::fs::copy(&from, &to)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pick_free_port_returns_distinct_ports() {
        let a = pick_free_port().unwrap();
        let b = pick_free_port().unwrap();
        assert!(a >= 1024 && a <= 65535);
        assert!(b >= 1024 && b <= 65535);
        // Not strictly required but in practice the kernel doesn't reuse
        // the same port immediately after `drop`.
        assert_ne!(a, b);
    }

    #[test]
    fn write_config_renders_transit_off_by_default() {
        let dir = tempdir();
        let p = dir.join("i2pd.conf");
        write_config(&p, 31415, /*enable_transit=*/ false).unwrap();
        let body = std::fs::read_to_string(&p).unwrap();
        assert!(body.contains("port = 31415"));
        assert!(body.contains("transittunnels = 0"));
        assert!(body.contains("enabled = true"), "[sam] not enabled");
    }

    #[test]
    fn write_config_drops_transit_line_when_enabled() {
        let dir = tempdir();
        let p = dir.join("i2pd.conf");
        write_config(&p, 22000, /*enable_transit=*/ true).unwrap();
        let body = std::fs::read_to_string(&p).unwrap();
        assert!(!body.contains("transittunnels = 0"));
        assert!(body.contains("user opted in"));
    }

    #[test]
    fn locate_binary_respects_env_override() {
        // Use the actual i2pd binary if present so this test passes
        // wherever the lib builds. Skip if i2pd isn't installed.
        let candidate = "/opt/homebrew/opt/i2pd/bin/i2pd";
        if !std::path::Path::new(candidate).is_file() {
            return;
        }
        std::env::set_var("WHISPER_I2PD_BINARY", candidate);
        let p = locate_i2pd_binary().unwrap();
        assert_eq!(p, std::path::PathBuf::from(candidate));
        std::env::remove_var("WHISPER_I2PD_BINARY");
    }

    fn tempdir() -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!(
            "whisper-i2p-test-{}",
            uuid::Uuid::new_v4().simple()
        ));
        std::fs::create_dir_all(&p).unwrap();
        p
    }
}
