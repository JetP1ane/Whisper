//! Noctis Whisper Desktop — library entry point.
//!
//! Wires the Tauri app, exposes IPC commands to the frontend, and owns the
//! global runtime state (vault, transport, db).

pub mod commands;
pub mod crypto;
pub mod db;
pub mod identity;
pub mod messaging;
pub mod profile;
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
            commands::conversation_messages,
            commands::conversation_security_summary,
            commands::conversation_set_disappear,
            commands::message_send,
            commands::message_send_detonating,
            commands::message_send_attachment,
            commands::room_create,
            commands::room_send,
            commands::attachment_load_data_url,
            commands::attachment_save_as,
            // relay
            commands::relay_status,
            commands::relay_set_url,
            commands::relay_connect,
            commands::relay_change_url,
            commands::cross_relay_stats,
            commands::messages_search,
            commands::notifications_get,
            commands::notifications_set,
            commands::notifications_test,
            // dashboard
            commands::security_status,
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
            // vault state, identity, and relay client).
            app.manage(arc);

            #[cfg(debug_assertions)]
            {
                if let Some(window) = app.get_webview_window("main") {
                    window.open_devtools();
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
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error running Noctis Whisper");
}
