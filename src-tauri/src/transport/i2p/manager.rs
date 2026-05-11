//! I2PManager — owns the i2pd subprocess lifecycle.
//!
//! Responsibilities:
//!
//! 1. **Locate the i2pd binary.** Dev: Homebrew at
//!    `/opt/homebrew/opt/i2pd/bin/i2pd`. Release: bundled inside
//!    `Whisper.app/Contents/Resources/i2pd` and signed alongside
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
///
/// Production: bundled inside `Whisper.app/Contents/Resources/
/// i2pd-bundle/i2pd`, with its dylibs alongside under `i2pd-bundle/lib/`.
/// The bundle is produced by `scripts/bundle-i2pd.sh` and copied into
/// the .app by Tauri's `bundle.resources` config in `tauri.conf.json`.
///
/// Dev: Homebrew at `/opt/homebrew/opt/i2pd/bin/i2pd`. Tests can set
/// `WHISPER_I2PD_BINARY` to point at a custom build.
fn locate_i2pd_binary() -> I2pResult<PathBuf> {
    // The env-override and brew fallbacks are dev affordances. In a
    // release build they're a downgrade: an attacker who can plant
    // `~/.zshrc` exports or a malicious /opt/homebrew binary controls
    // our network stack. Restrict to debug builds.
    if cfg!(debug_assertions) {
        if let Ok(p) = std::env::var("WHISPER_I2PD_BINARY") {
            let path = PathBuf::from(p);
            if path.is_file() {
                return Ok(path);
            }
        }
        // Project-local `i2pd-bundle/i2pd` next to Cargo.toml. This is
        // the same tree `build.rs` walked to embed the per-file SHA-256
        // manifest, so `verify_i2pd_pin` finds every dylib + cert in
        // the layout it expects. Without this preference, dev runs
        // would fall through to the homebrew binary below — which has
        // no companion `lib/` or `certificates/` siblings, and the
        // pin walk fails on the first dylib lookup.
        let src_bundle = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("i2pd-bundle")
            .join("i2pd");
        if src_bundle.is_file() {
            return Ok(src_bundle);
        }
    }
    // Bundled inside the .app. Walk up from the current exe path:
    // exe is at .../Contents/MacOS/<app>; go to Contents/Resources/
    // and into i2pd-bundle/.
    if let Ok(exe) = std::env::current_exe() {
        if let Some(macos_dir) = exe.parent() {
            if let Some(contents) = macos_dir.parent() {
                let bundled = contents
                    .join("Resources")
                    .join("i2pd-bundle")
                    .join("i2pd");
                if bundled.is_file() {
                    return Ok(bundled);
                }
            }
        }
    }
    if cfg!(debug_assertions) {
        let brew = PathBuf::from("/opt/homebrew/opt/i2pd/bin/i2pd");
        if brew.is_file() {
            return Ok(brew);
        }
        let brew_intel = PathBuf::from("/usr/local/opt/i2pd/bin/i2pd");
        if brew_intel.is_file() {
            return Ok(brew_intel);
        }
    }
    Err(I2pError::Subprocess(
        "i2pd binary not found (release builds require the bundled \
         Resources/i2pd-bundle/i2pd; debug builds may set WHISPER_I2PD_BINARY \
         or install via brew)"
            .into(),
    ))
}

/// Where to look for i2pd's certificate bundle (reseed certs + family
/// certs). i2pd needs these to bootstrap into the network on a fresh
/// datadir. Homebrew installs them into the Cellar; the bundled .app
/// keeps them next to the i2pd binary in `Resources/certificates/`.
fn locate_i2pd_certificates() -> Option<PathBuf> {
    if cfg!(debug_assertions) {
        if let Ok(p) = std::env::var("WHISPER_I2PD_CERTIFICATES") {
            let path = PathBuf::from(p);
            if path.is_dir() {
                return Some(path);
            }
        }
    }
    // Production: Resources/i2pd-bundle/certificates/ alongside the binary.
    if let Ok(exe) = std::env::current_exe() {
        if let Some(macos_dir) = exe.parent() {
            if let Some(contents) = macos_dir.parent() {
                let bundled = contents
                    .join("Resources")
                    .join("i2pd-bundle")
                    .join("certificates");
                if bundled.is_dir() {
                    return Some(bundled);
                }
            }
        }
    }
    if cfg!(debug_assertions) {
        let brew = PathBuf::from("/opt/homebrew/Cellar/i2pd/2.60.0/share/i2pd/certificates");
        if brew.is_dir() {
            return Some(brew);
        }
        let brew_intel = PathBuf::from("/usr/local/Cellar/i2pd/2.60.0/share/i2pd/certificates");
        if brew_intel.is_dir() {
            return Some(brew_intel);
        }
    }
    None
}

// Per-file SHA-256 manifest of `i2pd-bundle/`, generated at compile time
// by `build.rs` and emitted to OUT_DIR. Empty when the bundle wasn't
// present at build time (dev builds before `scripts/bundle-i2pd.sh`
// runs). The manifest covers the i2pd binary AND every dylib and
// certificate file under the bundle root.
include!(concat!(env!("OUT_DIR"), "/i2pd_bundle_manifest.rs"));

/// Verify every file under `i2pd-bundle/` matches the SHA-256 we
/// computed at build time. Refuses to spawn on any mismatch.
///
/// Why every file (NEW-3): the previous version pinned only the i2pd
/// executable, which left the dylibs and reseed certs unverified. The
/// dynamic pentest pass demonstrated that an attacker who can replace
/// `i2pd-bundle/lib/libcrypto.3.dylib` and ad-hoc re-sign it would be
/// loaded by dyld at i2pd spawn (i2pd has no hardened-runtime flag,
/// so library validation is not enforced for it). The manifest closes
/// that gap — any byte-level change to anything in the bundle is now
/// caught before we hand control to i2pd.
///
/// Skipped (with a warning) when the build-time manifest is empty.
/// Always skipped when the operator has explicitly pointed at a
/// custom binary via `WHISPER_I2PD_BINARY` — that's a development
/// affordance where the user is providing their own integrity
/// guarantee. The env override is gated on debug builds.
fn verify_i2pd_pin(path: &Path) -> I2pResult<()> {
    if cfg!(debug_assertions) && std::env::var_os("WHISPER_I2PD_BINARY").is_some() {
        tracing::info!(
            "i2p: pin check skipped (WHISPER_I2PD_BINARY override, debug build)"
        );
        return Ok(());
    }
    if I2PD_BUNDLE_MANIFEST.is_empty() {
        if !cfg!(debug_assertions) {
            return Err(I2pError::Subprocess(
                "i2pd bundle manifest missing in release build — refusing \
                 to spawn an unverified subprocess. Re-run \
                 scripts/bundle-i2pd.sh and rebuild."
                    .into(),
            ));
        }
        tracing::warn!(
            "i2p: pin manifest not embedded at build time — skipping integrity check (debug only)"
        );
        return Ok(());
    }

    // The manifest's relative paths are anchored at the bundle root.
    // Determine that root from the i2pd binary path the caller passed:
    // e.g. `/.../Contents/Resources/i2pd-bundle/i2pd` → `i2pd-bundle/`.
    let bundle_root = path.parent().ok_or_else(|| {
        I2pError::Subprocess("i2pd path has no parent directory".into())
    })?;

    // Debug-mode safety net: if `locate_i2pd_binary` fell through to a
    // homebrew install (no companion `lib/` next to the binary), the
    // manifest walk will fail on the very first dylib lookup. Detect
    // that case and skip the pin check with a clear log line, rather
    // than failing the whole spawn. Release builds NEVER reach this
    // path — `locate_i2pd_binary` won't return a brew binary in
    // release, and a missing bundle would have already errored above.
    if cfg!(debug_assertions) && !bundle_root.join("lib").is_dir() {
        tracing::warn!(
            "i2p: pin check skipped — i2pd at {} has no sibling lib/ \
             (debug build, likely a homebrew binary). To verify the pin \
             in dev, run scripts/bundle-i2pd.sh so a project-local \
             i2pd-bundle/ exists.",
            path.display()
        );
        return Ok(());
    }

    let mut verified: usize = 0;
    for (rel, expected_hex) in I2PD_BUNDLE_MANIFEST.iter() {
        let abs = bundle_root.join(rel);
        let bytes = std::fs::read(&abs).map_err(|e| {
            I2pError::Subprocess(format!(
                "i2pd pin: cannot read {} ({e})",
                abs.display()
            ))
        })?;
        let actual = sha256_hex(&bytes);
        if actual.as_str() != *expected_hex {
            tracing::error!(
                "i2p: pin mismatch on `{}` — refusing to spawn. expected={}, actual={}",
                rel,
                expected_hex,
                actual
            );
            return Err(I2pError::Subprocess(format!(
                "i2pd bundle integrity check failed for {} \
                 (expected {}, got {})",
                rel, expected_hex, actual
            )));
        }
        verified += 1;
    }
    tracing::info!(
        "i2p: pin verified ({} files, including dylibs and certs)",
        verified
    );
    Ok(())
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(bytes);
    hex::encode(h.finalize())
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

/// Kill any orphan i2pd subprocess that's still holding a flock on
/// `<i2p_dir>/i2pd.pid`.
///
/// Why this exists: brew's `cask` upgrade flow is "remove the old .app,
/// install the new .app." It does not reach into the OS process tree to
/// reap children. So when a user upgrades, the parent Whisper app is
/// killed (its executable on disk is gone) but the i2pd subprocess it
/// forked keeps running indefinitely. The new app then tries to spawn
/// its own i2pd, which fails to acquire the data dir's pid-file lock,
/// and the UI hangs at "Still connecting..." with no error surfaced.
///
/// We defend against that by reading the pid file on every start and,
/// if the PID inside is alive AND its executable path ends in
/// `i2pd-bundle/i2pd` (the safety check — never SIGKILL an unrelated
/// process whose PID happens to collide), terminating it before
/// launching the new instance. The path-suffix check matches our
/// binary regardless of which .app it was launched from, which is
/// exactly the orphan case (the orphan was launched from a now-removed
/// or now-renamed .app).
fn kill_orphan_i2pd(i2p_dir: &Path) {
    let pid_path = i2p_dir.join("i2pd.pid");
    let raw = match std::fs::read_to_string(&pid_path) {
        Ok(s) => s,
        Err(_) => return, // no pid file → nothing to clean
    };
    let pid: i32 = match raw.trim().parse() {
        Ok(p) => p,
        Err(_) => {
            let _ = std::fs::remove_file(&pid_path);
            return;
        }
    };
    if pid <= 0 {
        let _ = std::fs::remove_file(&pid_path);
        return;
    }

    // libc::kill(pid, 0) returns 0 if the process exists (and we have
    // permission to signal it); ESRCH otherwise.
    if unsafe { libc::kill(pid, 0) } != 0 {
        // Dead. Stale pid file left from a prior crash.
        let _ = std::fs::remove_file(&pid_path);
        return;
    }

    if !is_our_i2pd_process(pid) {
        // Live process at this PID but it isn't ours. PID reuse is rare
        // but real; refuse to touch an unrelated process. Leave the
        // pid file in place and let i2pd's own startup error out so the
        // user sees something explicit rather than a silent kill.
        tracing::warn!(
            "i2p: pid file points to live PID {pid} but the executable \
             at that PID is not our bundled i2pd; not touching it"
        );
        return;
    }

    tracing::info!(
        "i2p: orphan i2pd subprocess pid={pid} still running \
         (likely from a prior brew upgrade) — terminating before respawn"
    );
    unsafe { libc::kill(pid, libc::SIGTERM) };
    // Give it ~2s to exit on SIGTERM before escalating.
    for _ in 0..20 {
        std::thread::sleep(Duration::from_millis(100));
        if unsafe { libc::kill(pid, 0) } != 0 {
            break;
        }
    }
    if unsafe { libc::kill(pid, 0) } == 0 {
        let _ = unsafe { libc::kill(pid, libc::SIGKILL) };
        std::thread::sleep(Duration::from_millis(200));
    }
    let _ = std::fs::remove_file(&pid_path);
}

/// On macOS, resolve a PID's executable path via libproc and check
/// that it ends in `i2pd-bundle/i2pd`. The suffix match is what we want
/// — the orphan was launched from an .app that's since been replaced
/// or renamed, so the absolute path won't match the current bundle's
/// path, but the trailing `i2pd-bundle/i2pd` is invariant across our
/// builds (set by `scripts/bundle-i2pd.sh`).
fn is_our_i2pd_process(pid: i32) -> bool {
    #[cfg(target_os = "macos")]
    {
        let mut buf = vec![0u8; libc::PROC_PIDPATHINFO_MAXSIZE as usize];
        let len = unsafe {
            libc::proc_pidpath(pid, buf.as_mut_ptr() as *mut _, buf.len() as u32)
        };
        if len <= 0 {
            return false;
        }
        buf.truncate(len as usize);
        let path = String::from_utf8_lossy(&buf);
        path.ends_with("i2pd-bundle/i2pd")
    }
    #[cfg(not(target_os = "macos"))]
    {
        // Linux dev/test path: /proc/<pid>/exe is a symlink to the binary.
        let exe = std::fs::read_link(format!("/proc/{pid}/exe")).ok();
        exe.map(|p| p.to_string_lossy().ends_with("i2pd-bundle/i2pd"))
            .unwrap_or(false)
    }
}

/// Configuration for an `I2PManager` launch.
#[derive(Debug, Clone)]
pub struct I2pConfig {
    /// Per-profile data dir under which `i2p/` is created. Typically
    /// `<profile_data_dir>` from `crate::profile::data_dir()`.
    pub profile_dir: PathBuf,
    /// Whether to enable transit routing (forward encrypted traffic for
    /// other I2P users). Default `false` per Mod #1; Phase 10 onboarding
    /// flips this to true after the user opts in. Only honored when
    /// `source` is `Bundled` — external routers are configured by the
    /// user, not by Whisper.
    pub enable_transit: bool,
    /// Where the i2pd SAM bridge that Whisper talks to lives. Defaults
    /// to `Bundled`, which spawns the integrity-pinned i2pd we ship
    /// inside `.app/Contents/Resources/i2pd-bundle/`. `External` skips
    /// the spawn entirely and connects to a SAM endpoint the user
    /// supplies.
    pub source: I2pSource,
}

/// Selects whether Whisper spawns its own bundled i2pd or connects to
/// a user-supplied SAM bridge.
///
/// **Trust framing.** In `Bundled` mode, Whisper owns the entire
/// transport-layer trust boundary: the i2pd binary is SHA-256 pinned
/// (mismatches refuse to start), every nested dylib is signed with our
/// Developer ID, and the subprocess runs under Hardened Runtime. In
/// `External` mode the user is substituting their own router: Whisper
/// can only vouch for the SAM messages it sends and receives over the
/// loopback (or remote) socket, not for the router's binary, config,
/// peer selection, NetDB state, or anything else below the SAM bridge.
/// The UI surfaces this distinction explicitly when External is
/// enabled.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum I2pSource {
    /// Spawn the bundled, integrity-pinned i2pd subprocess on a
    /// randomized loopback SAM port. Default.
    Bundled,
    /// Connect to a user-supplied SAM bridge. Host is typically
    /// `127.0.0.1` (the user's own router on the same machine) but can
    /// be any host the user can reach — Whisper does not constrain it
    /// beyond the warnings in the UI. Port is the SAM v3 listener port
    /// (i2pd default is 7656; Java I2P default is also 7656).
    External { host: String, port: u16 },
}

impl Default for I2pSource {
    fn default() -> Self {
        Self::Bundled
    }
}

impl I2pSource {
    /// Returns true for `Bundled`.
    pub fn is_bundled(&self) -> bool {
        matches!(self, Self::Bundled)
    }
}

/// Phase-A pre-start state: i2pd subprocess up, SAM bridge ready, NetDB
/// reseeded, but no destination has been minted yet and no SAM session
/// exists. Held during the window between app launch and vault unlock
/// so the user's typing time covers the slowest part of cold-start.
///
/// Privacy guarantee: a `PreStartedI2pd` is **not observable** to peers
/// who know our destination. Only the master STREAM session created in
/// `finalize` publishes the leaseset to floodfill peers — until then,
/// i2pd is just an anonymous router building outbound tunnels for
/// nobody in particular.
///
/// `kill_on_drop` semantics on `child`: if the user closes the app
/// before unlocking, this struct is dropped and i2pd is reaped.
#[derive(Debug)]
pub struct PreStartedI2pd {
    /// `Some` in Bundled mode (the subprocess we spawned); `None` in
    /// External mode (we don't own the router's process).
    pub(crate) child: Option<Child>,
    /// `Some` in Bundled mode (we redirect i2pd stdout/stderr here);
    /// `None` in External mode (i2pd's own logs live wherever the
    /// user's router writes them).
    pub(crate) log_path: Option<PathBuf>,
    pub(crate) sam_addr: String,
    /// The `I2pSource` this pre-warm was started against. Used by the
    /// vault-unlock path to detect a mismatch with the user's *current*
    /// persisted preference (e.g. they opened Settings → Security and
    /// switched modes between app launch and first unlock) and discard
    /// the now-stale pre-warm before finalizing the transport.
    pub(crate) source: I2pSource,
}

impl PreStartedI2pd {
    /// SAM bridge address for the running i2pd subprocess.
    pub fn sam_addr(&self) -> &str {
        &self.sam_addr
    }

    /// The `I2pSource` this pre-warm was started against. Compared by
    /// the unlock path against the user's current persisted preference
    /// to detect mid-launch setting changes (e.g. user toggled
    /// external mode while the vault was still locked).
    pub fn source(&self) -> &I2pSource {
        &self.source
    }

    /// Take ownership and kill the subprocess. Use this on app shutdown
    /// when the vault was never unlocked, so we don't leak an orphan.
    /// No-op in External mode.
    pub async fn shutdown(mut self) {
        let Some(mut child) = self.child.take() else {
            return;
        };
        if let Some(pid) = child.id() {
            unsafe {
                libc::kill(pid as i32, libc::SIGTERM);
            }
        }
        let _ = tokio::time::timeout(Duration::from_secs(3), child.wait()).await;
        let _ = child.kill().await;
    }
}

/// Active i2pd subprocess + the master STREAM session that all Whisper
/// inbound/outbound streams ride on top of.
pub struct I2PManager {
    /// The subprocess we spawned. `Some` in Bundled mode (kept so the
    /// destructor can reap it); `None` in External mode (the router
    /// is the user's, not ours to manage).
    child: Option<Child>,
    /// Where the subprocess writes its log file (Bundled mode only).
    /// `None` in External mode.
    log_path: Option<PathBuf>,
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
    /// Phase A: spawn i2pd and wait for the SAM bridge to come up.
    ///
    /// This is the slow part of cold start (~10-30s reseed + ~10-30s
    /// tunnel build on a fresh datadir). It does NOT touch the DB —
    /// no destination is minted, no SAM session is created, no
    /// leaseset is published. Safe to run before vault unlock so the
    /// user's typing time overlaps with the network warm-up.
    ///
    /// On success: returns a `PreStartedI2pd` holding the running
    /// subprocess and SAM address. Hand it to [`Self::finalize`]
    /// after vault unlock to mint the destination and create the
    /// master STREAM session. If the user closes the app without
    /// unlocking, drop the `PreStartedI2pd` (kill_on_drop reaps i2pd).
    ///
    /// In [`I2pSource::External`] mode this method skips the spawn,
    /// the integrity pin, and the datadir setup entirely — it just
    /// probes the user-supplied SAM endpoint to fail fast if the
    /// external router is unreachable.
    pub async fn pre_start(cfg: I2pConfig) -> I2pResult<PreStartedI2pd> {
        match cfg.source.clone() {
            I2pSource::Bundled => Self::pre_start_bundled(cfg).await,
            I2pSource::External { host, port } => {
                Self::pre_start_external(host, port).await
            }
        }
    }

    /// External-router pre-start: connect to the user-supplied SAM
    /// bridge, probe HELLO with a short deadline, and return. No
    /// integrity check (we can't pin a binary we don't ship), no
    /// subprocess to manage, no cert copy. If the bridge isn't ready
    /// in 15s, fail with an actionable error.
    async fn pre_start_external(host: String, port: u16) -> I2pResult<PreStartedI2pd> {
        let sam_addr = format!("{host}:{port}");
        tracing::info!("i2p: using external SAM bridge at {sam_addr}");
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            if probe_sam(&sam_addr).await.is_ok() {
                break;
            }
            if Instant::now() > deadline {
                return Err(I2pError::Subprocess(format!(
                    "external SAM bridge at {sam_addr} did not respond to HELLO \
                     within 15s — is your i2pd running and is SAM enabled?"
                )));
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
        tracing::info!("i2p: external SAM bridge ready at {sam_addr}");
        Ok(PreStartedI2pd {
            child: None,
            log_path: None,
            sam_addr,
            source: I2pSource::External { host, port },
        })
    }

    /// Bundled-router pre-start: locate + integrity-pin our binary,
    /// prepare the datadir, write i2pd.conf, reap any orphan, then
    /// spawn i2pd and wait for SAM. The original `pre_start` body.
    async fn pre_start_bundled(cfg: I2pConfig) -> I2pResult<PreStartedI2pd> {
        let bin = locate_i2pd_binary()?;
        verify_i2pd_pin(&bin)?;
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
        // The I2P-network transport ports (NTCP2 + SSU2). i2pd defaults
        // to 4567 for both, which means a second instance on the same
        // host fails to bind and never joins the network — the SAM
        // bridge still starts, so the dashboard reads "Connected" but
        // no actual I2P traffic flows. Randomizing per-instance the
        // way we already do SAM fixes multi-profile dev + multi-user
        // testing on a single host.
        let net_port = pick_free_port()?;
        let conf_path = i2p_dir.join("i2pd.conf");
        write_config(&conf_path, sam_port, net_port, cfg.enable_transit)?;

        let log_path = i2p_dir.join("i2pd.log");
        // Truncate the log on every launch so the file doesn't grow
        // unboundedly across restarts.
        let log_file = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&log_path)?;
        let log_file_err = log_file.try_clone()?;

        // Reap any orphan i2pd from a prior app launch (e.g. brew
        // cask upgrade left the subprocess parentless) before spawning
        // ours — otherwise the new spawn fails to acquire the pid-file
        // flock and the SAM bridge never comes up.
        kill_orphan_i2pd(&i2p_dir);

        tracing::info!("i2p: spawning i2pd (sam={sam_addr}, datadir={})", i2p_dir.display());
        let mut child = Command::new(&bin)
            .arg(format!("--datadir={}", i2p_dir.display()))
            .arg(format!("--conf={}", conf_path.display()))
            .arg("--log=stdout")
            .stdin(Stdio::null())
            .stdout(Stdio::from(log_file))
            .stderr(Stdio::from(log_file_err))
            // M-20: don't inherit the parent's env. i2pd respects
            // HTTP_PROXY/HTTPS_PROXY for reseed downloads; if a user has
            // those set (or an attacker plants them in a shell rc) the
            // first-launch reseed traffic could be MITM'd. We re-supply
            // only the variables i2pd actually needs — `HOME` (for any
            // libc calls that resolve a fallback config) and `PATH`
            // limited to system locations.
            .env_clear()
            .env("HOME", std::env::var_os("HOME").unwrap_or_default())
            .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
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
        tracing::info!("i2p: SAM ready at {sam_addr} (pre-start complete)");

        Ok(PreStartedI2pd {
            child: Some(child),
            log_path: Some(log_path),
            sam_addr,
            source: I2pSource::Bundled,
        })
    }

    /// Phase B: mint or load the destination from the now-unlocked DB,
    /// then create the master STREAM session (which publishes our
    /// leaseset to floodfill peers — i.e. announces "this destination
    /// is online" to the network).
    ///
    /// Must be called with a `PreStartedI2pd` from [`Self::pre_start`]
    /// and an unlocked `Database`. Returns a fully ready `I2PManager`.
    pub async fn finalize(pre: PreStartedI2pd, db: Database) -> I2pResult<Self> {
        let PreStartedI2pd {
            child,
            log_path,
            sam_addr,
            // Informational on the pre-warm only — the manager identifies
            // its router by `sam_addr` + `Option<Child>`, not by source.
            source: _,
        } = pre;

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

        // Encrypted-leaseset DH-auth list construction is deferred:
        // i2pd rejects SESSION CREATE with an empty auth list, and we
        // don't yet cycle the session on contact-add. Plain LS2 keeps
        // the bootstrap working for both fresh installs and existing
        // users; the practical exposure is small because destinations
        // are only ever shared via signed bundles, not a public
        // directory.
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

    /// Convenience: pre_start then finalize back-to-back. Kept for
    /// callers that have an unlocked DB up-front and don't care about
    /// the pre-warm split (e.g. integration tests).
    pub async fn start(db: Database, cfg: I2pConfig) -> I2pResult<Self> {
        let pre = Self::pre_start(cfg).await?;
        Self::finalize(pre, db).await
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

    /// Path to the i2pd log file (per-profile). Bundled mode only —
    /// returns `None` when connected to an external router whose logs
    /// live wherever the user's router writes them.
    pub fn log_path(&self) -> Option<&Path> {
        self.log_path.as_deref()
    }

    /// PID of the i2pd subprocess we spawned, if any. Bundled mode
    /// only — returns `None` in External mode (we don't own the
    /// router's process). The egress audit uses this to enumerate
    /// i2pd's sockets separately.
    pub fn child_pid(&self) -> Option<u32> {
        self.child.as_ref().and_then(|c| c.id())
    }

    /// Borrow the secondary DB Mutex. Used by the queue worker so it
    /// can re-acquire the lock each tick without going through the
    /// vault.
    pub fn db_mutex(&self) -> &parking_lot::Mutex<Database> {
        &self.db
    }

    /// Graceful shutdown: drop the control socket (kills the session in
    /// i2pd) then SIGTERM the process. SIGKILL after 5s if it lingers.
    /// In External mode, only the control socket is torn down — we
    /// never signal a process we don't own.
    pub async fn shutdown(mut self) -> I2pResult<()> {
        // Closing the control socket tears down the session.
        // Take ownership of the BufReader's inner stream so we can call
        // shutdown explicitly — this signals EOF to i2pd faster than a
        // `drop` alone.
        if let Ok(()) = self._control.get_mut().shutdown().await {
            tracing::debug!("i2p: control socket shut down");
        }

        // External-router mode: we don't own the router, so we don't
        // try to signal it. Closing the control socket above is the
        // only cleanup we should do.
        let Some(mut child) = self.child.take() else {
            tracing::debug!("i2p: external router — leaving it running on shutdown");
            return Ok(());
        };

        // Bundled: try graceful exit first.
        if let Some(pid) = child.id() {
            unsafe {
                libc::kill(pid as i32, libc::SIGTERM);
            }
        }
        let timeout = tokio::time::timeout(Duration::from_secs(5), child.wait()).await;
        match timeout {
            Ok(Ok(status)) => {
                tracing::info!("i2p: i2pd exited cleanly ({status:?})");
            }
            _ => {
                tracing::warn!("i2p: i2pd did not exit in 5s, sending SIGKILL");
                let _ = child.kill().await;
            }
        }
        Ok(())
    }
}

/// Public SAM HELLO probe — used by `i2p_test_source` to validate an
/// external endpoint without persisting anything. Same semantics as
/// the internal readiness probe.
pub async fn sam_hello_probe(addr: &str) -> I2pResult<()> {
    probe_sam(addr).await
}

/// Public wrapper around `locate_i2pd_binary` + `verify_i2pd_pin`,
/// surfaced so the `i2p_test_source` command can check the bundled
/// router's integrity without paying the cost of spawning it. Fails
/// if the binary is missing or its SHA-256 manifest doesn't match.
pub fn verify_bundled_for_test() -> I2pResult<()> {
    let bin = locate_i2pd_binary()?;
    verify_i2pd_pin(&bin)?;
    Ok(())
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
/// wrote by hand for Phase 1, but with a randomized SAM port (Mod #1),
/// a randomized I2P-network listen port (so multiple profiles can run
/// on the same host), and transit routing wired to the user's preference.
fn write_config(
    path: &Path,
    sam_port: u16,
    net_port: u16,
    enable_transit: bool,
) -> std::io::Result<()> {
    let transit_line = if enable_transit {
        "# transit routing on (user opted in)"
    } else {
        "transittunnels = 0"
    };
    // The top-level `port` key controls both NTCP2 and SSU2. Setting it
    // here lets two i2pd instances coexist on the same host — neither
    // gets the default 4567, so neither loses the bind race.
    let body = format!(
        r#"# Generated by Whisper. DO NOT EDIT — regenerated on every launch.

port = {net_port}

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

/// Pull our identity X25519 private key out of the secondary DB. Used
/// to populate `i2cp.leaseSetPrivKey` so i2pd can decrypt encrypted
/// leasesets sent BY peers we've authorized ourselves with.
fn read_identity_x25519_priv(db: &Database) -> Option<[u8; 32]> {
    let mut stmt = db
        .conn
        .prepare("SELECT x25519_secret FROM identity WHERE id = 'self' LIMIT 1")
        .ok()?;
    let mut rows = stmt.query([]).ok()?;
    let row = rows.next().ok()??;
    let bytes: Vec<u8> = row.get(0).ok()?;
    if bytes.len() != 32 {
        return None;
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Some(arr)
}

/// Pull every known contact's X25519 public key from the secondary DB.
/// These become the authorized recipient list on our encrypted
/// leaseset — only peers in this list can resolve our destination via
/// the floodfills.
fn read_contact_x25519_pubs(db: &Database) -> Vec<[u8; 32]> {
    let mut stmt = match db.conn.prepare("SELECT x25519_public FROM contacts") {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let rows = stmt
        .query_map([], |r| r.get::<_, Vec<u8>>(0))
        .ok();
    let Some(rows) = rows else { return Vec::new() };
    rows.flatten()
        .filter_map(|v| {
            if v.len() == 32 {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&v);
                Some(arr)
            } else {
                None
            }
        })
        .collect()
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
        write_config(&p, 31415, 18888, /*enable_transit=*/ false).unwrap();
        let body = std::fs::read_to_string(&p).unwrap();
        assert!(body.contains("port = 18888"), "net port not written");
        assert!(body.contains("port = 31415"), "sam port not written");
        assert!(body.contains("transittunnels = 0"));
        assert!(body.contains("enabled = true"), "[sam] not enabled");
    }

    #[test]
    fn write_config_drops_transit_line_when_enabled() {
        let dir = tempdir();
        let p = dir.join("i2pd.conf");
        write_config(&p, 22000, 18889, /*enable_transit=*/ true).unwrap();
        let body = std::fs::read_to_string(&p).unwrap();
        assert!(!body.contains("transittunnels = 0"));
        assert!(body.contains("user opted in"));
    }

    #[test]
    fn write_config_uses_distinct_sam_and_net_ports() {
        let dir = tempdir();
        let p = dir.join("i2pd.conf");
        write_config(&p, 12345, 23456, false).unwrap();
        let body = std::fs::read_to_string(&p).unwrap();
        // Both ports appear, distinct.
        assert!(body.contains("port = 23456"));
        assert!(body.contains("port = 12345"));
    }

    // The env override is a debug-only affordance per HIGH-3 — release
    // builds intentionally ignore WHISPER_I2PD_BINARY so a planted env
    // var can't redirect a signed app to a malicious binary. The test
    // only makes sense for the debug branch.
    #[cfg(debug_assertions)]
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

    /// NEW-3 regression: verify_i2pd_pin must catch byte-tampering of any
    /// file in the bundle (not just the i2pd executable). Tampers a dylib
    /// and a certificate in turn and confirms each yields a diagnostic
    /// rejection. Skipped in debug because the manifest may be empty.
    #[cfg(not(debug_assertions))]
    #[test]
    fn verify_i2pd_pin_catches_dylib_tampering() {
        // Copy the real bundle to a tempdir so we can mutate without
        // racing with a real launch.
        let src = std::path::Path::new("i2pd-bundle");
        if !src.is_dir() {
            return; // dev cargo without bundle staged — nothing to test
        }
        let dst = tempdir();
        copy_dir_all(src, &dst).unwrap();

        let i2pd = dst.join("i2pd");
        // Sanity: clean pin passes.
        verify_i2pd_pin(&i2pd).expect("clean bundle should verify");

        // Tamper a dylib (1 byte at the file's 0x100 offset).
        let target = dst.join("lib/libcrypto.3.dylib");
        if target.is_file() {
            let mut bytes = std::fs::read(&target).unwrap();
            bytes[0x100] ^= 0xFF;
            std::fs::write(&target, &bytes).unwrap();
            let err = verify_i2pd_pin(&i2pd).expect_err("tampered dylib must fail");
            let msg = err.to_string();
            assert!(
                msg.contains("lib/libcrypto.3.dylib"),
                "diagnostic should name the offending file; got: {msg}"
            );
            assert!(msg.to_ascii_lowercase().contains("integrity"));
            // Restore for the cert tampering branch.
            bytes[0x100] ^= 0xFF;
            std::fs::write(&target, &bytes).unwrap();
            verify_i2pd_pin(&i2pd).expect("restored dylib should verify");
        }

        // Tamper a reseed cert.
        let cert = dst.join("certificates/reseed/i2p-reseed_at_mk16.de.crt");
        if cert.is_file() {
            let mut cb = std::fs::read(&cert).unwrap();
            cb[0] ^= 0xFF;
            std::fs::write(&cert, &cb).unwrap();
            let err = verify_i2pd_pin(&i2pd).expect_err("tampered cert must fail");
            assert!(
                err.to_string().contains("certificates/reseed/i2p-reseed_at_mk16.de.crt"),
                "diagnostic should name the cert"
            );
        }
    }

    fn copy_dir_all(src: &std::path::Path, dst: &std::path::Path) -> std::io::Result<()> {
        std::fs::create_dir_all(dst)?;
        for entry in std::fs::read_dir(src)? {
            let entry = entry?;
            let ty = entry.file_type()?;
            let from = entry.path();
            let to = dst.join(entry.file_name());
            if ty.is_dir() {
                copy_dir_all(&from, &to)?;
            } else if ty.is_file() {
                std::fs::copy(&from, &to)?;
            }
        }
        Ok(())
    }

    fn tempdir() -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!(
            "whisper-i2p-test-{}",
            uuid::Uuid::new_v4().simple()
        ));
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    /// Smoke test for [`I2pSource::External`]: when set against a SAM
    /// bridge that responds, `pre_start` should succeed and return a
    /// `PreStartedI2pd` whose `child` is `None` (we didn't spawn one)
    /// and whose `sam_addr` matches the configured endpoint.
    ///
    /// Requires a live SAM bridge — set
    /// `WHISPER_I2P_EXTERNAL_TEST=127.0.0.1:7666` to enable. CI and
    /// machines without a router skip silently.
    #[tokio::test]
    async fn external_pre_start_against_live_sam() {
        let Ok(endpoint) = std::env::var("WHISPER_I2P_EXTERNAL_TEST") else {
            eprintln!("skipping: WHISPER_I2P_EXTERNAL_TEST not set");
            return;
        };
        // Sanity: SAM HELLO must work first, else there's no point.
        if sam_hello_probe(&endpoint).await.is_err() {
            eprintln!("skipping: no SAM bridge at {endpoint}");
            return;
        }
        let (host, port) = endpoint.rsplit_once(':').unwrap();
        let port: u16 = port.parse().unwrap();

        let cfg = I2pConfig {
            profile_dir: tempdir(),
            enable_transit: false,
            source: I2pSource::External {
                host: host.to_string(),
                port,
            },
        };

        let pre = I2PManager::pre_start(cfg)
            .await
            .expect("pre_start_external should succeed");

        assert!(
            pre.child.is_none(),
            "external mode must not spawn an i2pd subprocess"
        );
        assert!(
            pre.log_path.is_none(),
            "external mode has no log path of its own"
        );
        assert_eq!(pre.sam_addr(), endpoint);

        // shutdown() is a no-op in external mode; should not panic or
        // try to signal a process we don't own.
        pre.shutdown().await;
    }

    /// External mode with an unreachable endpoint should fail fast
    /// (well under the 15s deadline in practice — TCP RST on loopback
    /// is immediate). The error message must name the host:port so the
    /// user knows what to fix.
    #[tokio::test]
    async fn external_pre_start_unreachable_fails_with_clear_message() {
        // Port 1 is reserved and never listens; connect attempts return
        // ECONNREFUSED immediately.
        let cfg = I2pConfig {
            profile_dir: tempdir(),
            enable_transit: false,
            source: I2pSource::External {
                host: "127.0.0.1".to_string(),
                port: 1,
            },
        };
        let err = I2PManager::pre_start(cfg)
            .await
            .expect_err("unreachable external must fail");
        let msg = err.to_string();
        assert!(
            msg.contains("127.0.0.1:1"),
            "error should name the endpoint, got: {msg}"
        );
    }
}
