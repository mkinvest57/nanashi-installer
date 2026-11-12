#[macro_use]
mod account;
#[macro_use]
mod device;
mod error;
mod nanashi;
mod operation;
mod pairing;
mod secure_storage;
mod sideload;

use crate::{
    account::{
        cancel_login, delete_account, invalidate_account, logged_in_as, login_new, login_stored,
    },
    device::{
        DeviceInfoMutex, PairingCancelToken, cancel_pairing, list_devices, set_selected_device,
    },
    nanashi::{install_nanashi_manager_operation, nanashi_bootstrap_configuration},
    pairing::has_stored_rppairing,
    secure_storage::keyring_available,
    sideload::SideloaderMutex,
};
use tauri::Manager;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_process::init())
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_store::Builder::new().build())
        .setup(|app| {
            // Authentication libraries can include request details in diagnostics.
            // This installer does not persist or forward dependency logs, panic
            // payloads, credentials, or pairing material to the frontend.
            app.manage(DeviceInfoMutex::new(None));
            app.manage(SideloaderMutex::new(None));
            app.manage(PairingCancelToken::new(None));
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            login_new,
            invalidate_account,
            logged_in_as,
            login_stored,
            delete_account,
            cancel_login,
            list_devices,
            set_selected_device,
            keyring_available,
            cancel_pairing,
            has_stored_rppairing,
            nanashi_bootstrap_configuration,
            install_nanashi_manager_operation,
        ])
        .run(tauri::generate_context!())
        .expect("error while running Nanashi Installer");
}
