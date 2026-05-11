//! Whisper Desktop — library entry point.
//!
//! Wires the Tauri app, exposes IPC commands to the frontend, and owns the
//! global runtime state (vault, transport, db).

pub mod commands;
pub mod crypto;
pub mod db;
pub mod identity;
pub mod messaging;
pub mod profile;
pub mod security;
pub mod state;
pub mod transport;

use state::{AppPaths, AppState};
use tauri::Manager;

pub use profile::name as profile_name;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_clipboard_manager::init())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_notification::init())
        .invoke_handler(tauri::generate_handler![
            // identity / vault
            commands::vault_status,
            commands::vault_setup,
            commands::vault_recover_from_seed,
            commands::vault_view_recovery_phrase,
            commands::vault_unlock,
            commands::vault_lock,
            commands::identity_get,
            commands::identity_invite_link,
            commands::identity_publish_bundle,
            // contacts
            commands::contact_list,
            commands::contact_add_by_alias,
            commands::contact_add_by_link,
            commands::contact_accept_request,
            commands::contact_decline_request,
            commands::contact_verify,
            commands::contact_set_nickname,
            commands::contact_safety_numbers,
            commands::conversation_delete,
            // conversations + messages
            commands::conversation_list,
            commands::conversation_open,
            commands::conversation_mark_read,
            commands::conversation_messages,
            commands::conversation_security_summary,
            commands::conversation_set_disappear,
            commands::message_send,
            commands::message_send_detonating,
            commands::message_send_attachment,
            commands::message_react,
            commands::room_create,
            commands::room_send,
            commands::attachment_load_data_url,
            commands::attachment_save_as,
            // transport (I2P)
            commands::i2p_status,
            commands::i2p_get_transit_optin,
            commands::i2p_set_transit_optin,
            commands::i2p_get_source,
            commands::i2p_set_source,
            commands::i2p_test_source,
            commands::messages_search,
            commands::notifications_get,
            commands::notifications_set,
            commands::notifications_test,
            // dashboard
            commands::security_status,
            commands::egress_audit,
        ])
        .setup(|app| {
            // Profile-scoped data directory: lets multiple instances run
            // side-by-side for multi-user testing.  Set `NOCTIS_PROFILE`
            // (e.g. `alice`, `bob`) to pick a profile; defaults to `default`.
            let db_file = profile::db_file();
            tracing::info!(
                "starting profile `{}` with db {}",
                profile::name(),
                db_file.display()
            );

            // Install the AppState into Tauri's StateManager *and* into a
            // process-global Arc so background tokio tasks (the inbound
            // pump) can clone an owned handle.
            let app_state = AppState::new(AppPaths { db_file });
            let arc = std::sync::Arc::new(app_state);
            commands::install_shared_state(arc.clone());
            // `manage` requires `Send + Sync + 'static` — pass the shared
            // Arc so the StateManager and the OnceCell point at the same
            // backing AppState (commands and the pump observe identical
            // vault state, identity, and relay client). Clone so we can
            // hand a copy to the pre-warm setup further down.
            app.manage(arc.clone());

            // Devtools auto-open is opt-in. Default-on was annoying for
            // hands-on dual-window testing; set WHISPER_OPEN_DEVTOOLS=1
            // when you actually want the inspector at launch. Devtools
            // are still compiled in for debug builds, so right-click ->
            // Inspect Element keeps working without the env var.
            #[cfg(debug_assertions)]
            {
                if std::env::var_os("WHISPER_OPEN_DEVTOOLS").is_some() {
                    if let Some(window) = app.get_webview_window("main") {
                        window.open_devtools();
                    }
                }
            }
            // Log to a per-profile file so we can debug the release build.
            // Cocoa apps detach stdout/stderr by default, which is why
            // tracing-subscriber's stdout output doesn't show up.
            let log_path = profile::data_dir().join("noctis.log");
            if let Ok(file) = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&log_path)
            {
                tracing_subscriber::fmt()
                    .with_max_level(tracing::Level::INFO)
                    .with_writer(file)
                    .with_ansi(false)
                    .try_init()
                    .ok();
                tracing::info!("log file: {}", log_path.display());
            } else {
                tracing_subscriber::fmt()
                    .with_max_level(tracing::Level::INFO)
                    .try_init()
                    .ok();
            }
            // macOS menu-bar helper: keep the app + i2pd running when the
            // user closes the main window. Caveat #6 in the I2P design
            // proposal — without this, "must be online to deliver"
            // becomes "must keep the app window open to deliver,"
            // because i2pd dies when the process exits. This pattern
            // matches Discord/Slack/Spotify on macOS — close hides,
            // explicit Quit from the tray actually exits.
            install_tray(app)?;

            // I2P pre-warm: kick off i2pd subprocess + reseed + outbound
            // tunnel build *now*, while the user is still typing their
            // passphrase. Phase A doesn't touch the DB and doesn't
            // publish our destination — those wait for vault unlock —
            // so this is privacy-safe. By the time `vault_unlock` fires
            // it grabs the pre-warmed handle and only has to do the
            // ~3-5s SAM-session-create dance, not the 30-90s cold path.
            //
            // If the user closes the app without unlocking, the prewarm
            // slot drops on shutdown and i2pd is reaped via kill_on_drop.
            let prewarm_state = std::sync::Arc::clone(&arc);
            // Use `tauri::async_runtime::spawn` rather than `tokio::spawn`:
            // the setup callback fires before the tokio runtime context
            // is attached to this thread, so a bare tokio::spawn panics
            // with "no reactor running". Tauri's runtime handle is
            // already initialized at this point and queues the future
            // for the runtime that takes over a few ms later.
            let handle = tauri::async_runtime::spawn(async move {
                let profile_dir = profile::data_dir();
                let enable_transit = false; // mirrors the unlock-path default
                // Honor the user's persisted i2pd-source preference (Bundled
                // by default; External when they've explicitly opted in via
                // Settings → Security). Pre-warm before vault unlock, so we
                // can't read the SQLCipher settings table — the preference
                // lives in a plaintext JSON in the profile dir specifically
                // so this pre-warm path can resolve it.
                let source = crate::transport::i2p::runtime::read_persisted_source(
                    &profile_dir,
                );
                tracing::info!(
                    "i2p: starting pre-warm (phase A, source={})",
                    if source.is_bundled() { "bundled" } else { "external" }
                );
                match crate::transport::i2p::lifecycle::pre_start(
                    profile_dir,
                    enable_transit,
                    source,
                )
                .await
                {
                    Ok(pre) => {
                        tracing::info!(
                            "i2p: pre-warm complete (sam={}); waiting for vault unlock",
                            pre.sam_addr()
                        );
                        let mut slot = prewarm_state.i2p_prewarm.lock().await;
                        *slot = Some(pre);
                    }
                    Err(e) => {
                        tracing::warn!(
                            "i2p: pre-warm failed: {e:#} — vault_unlock will fall back to the cold path"
                        );
                    }
                }
            });
            // Hand the JoinHandle to vault_unlock so it can await
            // pre-warm completion before deciding warm-vs-cold path.
            *arc.i2p_prewarm_handle.lock() = Some(handle);

            Ok(())
        })
        .on_window_event(|window, event| {
            // Intercept the user clicking the close button on the main
            // window: hide instead of letting the OS close+exit. The
            // tray icon's "Quit Whisper" menu item is the only way to
            // actually exit.
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                if window.label() == "main" {
                    let _ = window.hide();
                    api.prevent_close();
                }
            }
        })
        .run(tauri::generate_context!())
        .expect("error running Whisper");
}

fn install_tray(app: &tauri::App) -> tauri::Result<()> {
    use tauri::menu::{Menu, MenuItem};
    use tauri::tray::{MouseButton, TrayIconBuilder, TrayIconEvent};
    use tauri::Manager;

    let open_item = MenuItem::with_id(app, "open", "Open Whisper", true, None::<&str>)?;
    let quit_item = MenuItem::with_id(app, "quit", "Quit Whisper", true, None::<&str>)?;
    let menu = Menu::with_items(app, &[&open_item, &quit_item])?;

    TrayIconBuilder::with_id("noctis-whisper-tray")
        // Render the Whisper waveform directly into an RGBA buffer. We
        // mirror the geometry of public/noctis_whisper_icon.svg but
        // strip the colour — macOS template-image semantics replace the
        // RGB with the system tint (white in dark menu bars, black in
        // light, dimmed when the app is inactive). The varying alpha
        // recreates the centre-emphasised fade of the brand mark.
        .icon(build_tray_template_icon())
        .icon_as_template(true)
        .tooltip("Whisper")
        .menu(&menu)
        .show_menu_on_left_click(false)
        .on_menu_event(|app, event| match event.id.as_ref() {
            "open" => {
                if let Some(w) = app.get_webview_window("main") {
                    let _ = w.show();
                    let _ = w.set_focus();
                }
            }
            "quit" => {
                tracing::info!("tray: Quit selected — exiting");
                app.exit(0);
            }
            _ => {}
        })
        .on_tray_icon_event(|tray, event| {
            // Left-click on the tray icon shows the main window — same
            // behavior most macOS menu-bar apps adopt. Right-click /
            // long-press still opens the menu.
            if let TrayIconEvent::Click { button: MouseButton::Left, .. } = event {
                if let Some(w) = tray.app_handle().get_webview_window("main") {
                    let _ = w.show();
                    let _ = w.set_focus();
                }
            }
        })
        .build(app)?;
    Ok(())
}

/// Build the menubar tray icon as a 88×88 RGBA bitmap, matching the
/// 7-bar Whisper waveform from `public/noctis_whisper_icon.svg` but
/// with all colour stripped — pure black with per-bar alpha. Set as
/// a macOS template image, the OS handles tinting:
///   * dark menu bar → white bars
///   * light menu bar → black bars
///   * app inactive → dimmed
///
/// 88×88 is a 4× supersample of the 22pt menubar slot; macOS scales
/// down with antialiasing so the bars stay crisp on retina displays.
/// We use programmatic drawing rather than baking out a PNG so the
/// icon ships in the binary with no external converter dependency
/// (resvg / librsvg / ImageMagick) and no checked-in raster asset.
fn build_tray_template_icon() -> tauri::image::Image<'static> {
    const W: u32 = 88;
    const H: u32 = 88;
    let mut rgba = vec![0u8; (W * H * 4) as usize];

    // Bar geometry, scaled from the 1024-unit source viewBox at
    // factor 88/1024 ≈ 0.086. Alpha values match the source's
    // luminance progression (lightest outer bars at 0xD7 → mid
    // outer at 0xBD → inner at 0x8F → centre at full opacity).
    let bars: &[(u32, u32, u32, u32, u8)] = &[
        // (x, y, width, height, alpha)
        (15, 39, 4, 10, 0xD7),
        (24, 33, 4, 21, 0xBD),
        (33, 27, 4, 35, 0x8F),
        (42, 19, 4, 50, 0xFF), // centre bar
        (51, 27, 4, 35, 0x8F),
        (60, 33, 4, 21, 0xBD),
        (69, 39, 4, 10, 0xD7),
    ];

    for &(bx, by, bw, bh, alpha) in bars {
        for y in by..(by + bh) {
            for x in bx..(bx + bw) {
                let i = ((y * W + x) * 4) as usize;
                // Black RGB; alpha carries the brand fade. macOS
                // replaces RGB with the menubar tint at render time.
                rgba[i] = 0;
                rgba[i + 1] = 0;
                rgba[i + 2] = 0;
                rgba[i + 3] = alpha;
            }
        }
    }

    tauri::image::Image::new_owned(rgba, W, H)
}
