use std::sync::Mutex;

use idevice::{
    IdeviceService,
    lockdown::LockdownClient,
    provider::UsbmuxdProvider,
    usbmuxd::{Connection, UsbmuxdAddr, UsbmuxdConnection},
};
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, State};
use tokio_util::sync::CancellationToken;

use crate::{error::AppError, pairing::pairing_file};

#[derive(Deserialize, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct DeviceInfo {
    pub name: String,
    pub id: u32,
    pub udid: String,
    pub connection_type: String,
    pub version: String,
}

#[derive(Deserialize, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct DeviceInfoWithPairing {
    pub info: DeviceInfo,
    pub pairing: Vec<u8>,
}

pub type DeviceInfoMutex = Mutex<Option<DeviceInfoWithPairing>>;
pub type PairingCancelToken = Mutex<Option<CancellationToken>>;

// Selection, cancellation and commit share one lock order: cancellation first,
// selected device second. A cancelled request can never replace the selection.
struct PairingAttempt<'a> {
    cancel_state: &'a PairingCancelToken,
    token: CancellationToken,
}

impl<'a> PairingAttempt<'a> {
    fn begin(cancel_state: &'a PairingCancelToken, device_state: &DeviceInfoMutex) -> Self {
        let token = CancellationToken::new();
        let mut current = cancel_state.lock().unwrap();
        if let Some(previous) = current.replace(token.clone()) {
            previous.cancel();
        }
        *device_state.lock().unwrap() = None;
        Self {
            cancel_state,
            token,
        }
    }
}

impl Drop for PairingAttempt<'_> {
    fn drop(&mut self) {
        self.token.cancel();
        self.cancel_state.lock().unwrap().take();
    }
}

fn commit_selected_device(
    cancel_state: &PairingCancelToken,
    device_state: &DeviceInfoMutex,
    token: &CancellationToken,
    device: DeviceInfoWithPairing,
) -> Result<(), AppError> {
    let _cancel = cancel_state.lock().unwrap();
    if token.is_cancelled() {
        return Err(AppError::Canceled("Association de l’iPhone".into()));
    }
    *device_state.lock().unwrap() = Some(device);
    Ok(())
}

fn cancel_pairing_selection(cancel_state: &PairingCancelToken, device_state: &DeviceInfoMutex) {
    let mut current = cancel_state.lock().unwrap();
    if let Some(token) = current.take() {
        token.cancel();
    }
    *device_state.lock().unwrap() = None;
}

#[tauri::command]
pub async fn list_devices() -> Result<Vec<Result<DeviceInfo, AppError>>, AppError> {
    let mut usbmuxd = get_usbmuxd().await?;

    let devs = usbmuxd.get_devices().await.map_err(|e| {
        AppError::Usbmuxd("Failed to list devices from usbmuxd".into(), e.to_string())
    })?;
    if devs.is_empty() {
        return Ok(vec![]);
    }

    let usbmuxd_addr = UsbmuxdAddr::from_env_var().map_err(|e| {
        AppError::Usbmuxd(
            "Invalid usbmuxd address from environment".into(),
            e.to_string(),
        )
    })?;

    let device_info_futures: Vec<_> = devs
        .iter()
        .map(|d| {
            let usbmuxd_addr = usbmuxd_addr.clone();
            async move {
                let provider = d.to_provider(usbmuxd_addr, "iloader");
                let device_uid = d.device_id;
                let connection_type = match d.connection_type {
                    Connection::Usb => "USB",
                    Connection::Network(_) => "Network",
                    Connection::Unknown(_) => "Unknown",
                }
                .to_string();

                let mut lockdown_client =
                    LockdownClient::connect(&provider).await.map_err(|e| {
                        eprintln!("Unable to connect to lockdown for {}: {e:?}", d.udid);
                        AppError::DeviceComsWithMessage(
                            "Unable to connect to lockdown".into(),
                            e.to_string(),
                        )
                    })?;

                let device_name_value = lockdown_client
                    .get_value(Some("DeviceName"), None)
                    .await
                    .map_err(|e| {
                    eprintln!("Failed to fetch DeviceName for {}: {e:?}", d.udid);
                    AppError::DeviceComsWithMessage(
                        "Failed to fetch DeviceName".into(),
                        e.to_string(),
                    )
                })?;

                let device_name = device_name_value.as_string().ok_or_else(|| {
                    eprintln!("DeviceName for {} was not a string", d.udid);
                    AppError::DeviceComs("DeviceName was not a string".into())
                })?;

                let version_value = lockdown_client
                    .get_value(Some("ProductVersion"), None)
                    .await
                    .map_err(|e| {
                        eprintln!("Failed to fetch ProductVersion for {}: {e:?}", d.udid);
                        AppError::DeviceComsWithMessage(
                            "Failed to fetch ProductVersion".into(),
                            e.to_string(),
                        )
                    })?;

                let version = version_value.as_string().ok_or_else(|| {
                    eprintln!("ProductVersion for {} was not a string", d.udid);
                    AppError::DeviceComs("Product version was not a string".into())
                })?;

                Ok::<DeviceInfo, AppError>(DeviceInfo {
                    name: device_name.to_string(),
                    id: device_uid,
                    udid: d.udid.clone(),
                    connection_type,
                    version: version.to_string(),
                })
            }
        })
        .collect();

    let device_infos = futures::future::join_all(device_info_futures).await;
    Ok(device_infos)
}

#[tauri::command]
pub async fn set_selected_device(
    app: AppHandle,
    device_state: State<'_, DeviceInfoMutex>,
    cancel_state: State<'_, PairingCancelToken>,
    device: Option<DeviceInfo>,
) -> Result<(), AppError> {
    let _operation = crate::nanashi::begin_exclusive_operation()?;
    let Some(device) = device else {
        cancel_pairing_selection(&cancel_state, &device_state);
        return Ok(());
    };
    // Register cancellation before the first await, including USB connection.
    let attempt = PairingAttempt::begin(&cancel_state, &device_state);
    let mut usbmuxd = tokio::select! {
        _ = attempt.token.cancelled() => return Err(AppError::Canceled("Association de l’iPhone".into())),
        connection = get_usbmuxd() => connection?,
    };
    let pairing = pairing_file(&app, &device, &mut usbmuxd, attempt.token.clone()).await?;
    commit_selected_device(
        &cancel_state,
        &device_state,
        &attempt.token,
        DeviceInfoWithPairing {
            info: device,
            pairing,
        },
    )
}

#[tauri::command]
pub async fn cancel_pairing(
    cancel_state: State<'_, PairingCancelToken>,
    device_state: State<'_, DeviceInfoMutex>,
) -> Result<(), AppError> {
    // Cancellation must remain available while the exclusive operation is held.
    cancel_pairing_selection(&cancel_state, &device_state);
    Ok(())
}

pub async fn get_usbmuxd() -> Result<UsbmuxdConnection, AppError> {
    UsbmuxdConnection::default()
        .await
        .map_err(|e| AppError::Usbmuxd("Failed to connect to usbmuxd".into(), e.to_string()))
}

pub async fn get_provider(device_info: &DeviceInfo) -> Result<UsbmuxdProvider, AppError> {
    get_provider_from_connection(device_info, &mut (get_usbmuxd().await?)).await
}

pub async fn get_provider_from_connection(
    device_info: &DeviceInfo,
    connection: &mut UsbmuxdConnection,
) -> Result<UsbmuxdProvider, AppError> {
    let device = connection
        .get_device(&device_info.udid)
        .await
        .map_err(|e| {
            AppError::DeviceComsWithMessage("Failed to get device".into(), e.to_string())
        })?;

    let provider = device.to_provider(UsbmuxdAddr::from_env_var().unwrap(), "iloader");
    Ok(provider)
}

#[cfg(test)]
mod selection_tests {
    use super::*;
    use std::sync::{Arc, Barrier};

    fn phone() -> DeviceInfoWithPairing {
        DeviceInfoWithPairing {
            info: DeviceInfo {
                name: "Test phone".into(),
                id: 1,
                udid: "PHONE-B".into(),
                connection_type: "USB".into(),
                version: "27.0".into(),
            },
            pairing: vec![1, 2, 3],
        }
    }

    #[test]
    fn cancelled_pairing_never_commits_a_late_result() {
        let cancel = PairingCancelToken::new(None);
        let selected = DeviceInfoMutex::new(Some(phone()));
        let attempt = PairingAttempt::begin(&cancel, &selected);
        assert!(selected.lock().unwrap().is_none());
        cancel_pairing_selection(&cancel, &selected);
        assert!(commit_selected_device(&cancel, &selected, &attempt.token, phone()).is_err());
        assert!(selected.lock().unwrap().is_none());
    }

    #[test]
    fn cancellation_and_commit_race_always_ends_without_a_selected_phone() {
        for _ in 0..64 {
            let token = CancellationToken::new();
            let cancel = Arc::new(PairingCancelToken::new(Some(token.clone())));
            let selected = Arc::new(DeviceInfoMutex::new(None));
            let start = Arc::new(Barrier::new(2));
            let commit = {
                let cancel = cancel.clone();
                let selected = selected.clone();
                let start = start.clone();
                std::thread::spawn(move || {
                    start.wait();
                    let _ = commit_selected_device(&cancel, &selected, &token, phone());
                })
            };
            start.wait();
            cancel_pairing_selection(&cancel, &selected);
            commit.join().unwrap();
            assert!(selected.lock().unwrap().is_none());
        }
    }
}
