use std::{collections::HashSet, sync::Mutex, time::Duration};

use idevice::{
    IdeviceService,
    lockdown::LockdownClient,
    provider::UsbmuxdProvider,
    usbmuxd::{Connection, UsbmuxdAddr, UsbmuxdConnection, UsbmuxdDevice},
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

const USB_TIMEOUT: Duration = Duration::from_secs(5);
const TRUST_TIMEOUT: Duration = Duration::from_secs(120);

// The wizard promises a cabled installation. A wireless advertisement may be
// stale or arrive before the USB row for the same phone.
fn wired_devices(devices: Vec<UsbmuxdDevice>) -> impl Iterator<Item = UsbmuxdDevice> {
    let mut seen = HashSet::new();
    devices
        .into_iter()
        .filter(move |d| d.connection_type == Connection::Usb && seen.insert(d.udid.clone()))
}

async fn enumerate_usb(connection: &mut UsbmuxdConnection) -> Result<Vec<UsbmuxdDevice>, AppError> {
    tokio::time::timeout(USB_TIMEOUT, connection.get_devices())
        .await
        .map_err(|_| AppError::Usbmuxd("USB discovery timed out".into(), String::new()))?
        .map_err(|_| AppError::Usbmuxd("USB discovery unavailable".into(), String::new()))
}

fn usb_address() -> Result<UsbmuxdAddr, AppError> {
    UsbmuxdAddr::from_env_var()
        .map_err(|_| AppError::Usbmuxd("Invalid usbmux address".into(), String::new()))
}

async fn describe_device(d: UsbmuxdDevice, address: UsbmuxdAddr) -> Result<DeviceInfo, AppError> {
    let error = || AppError::DeviceComs("Unable to read iPhone information over USB".into());
    let provider = d.to_provider(address, "iloader");
    let mut lockdown = LockdownClient::connect(&provider)
        .await
        .map_err(|_| error())?;
    let version = lockdown
        .get_value(Some("ProductVersion"), None)
        .await
        .map_err(|_| error())?;
    let version = version.as_string().ok_or_else(error)?.to_owned();
    let name = lockdown
        .get_value(Some("DeviceName"), None)
        .await
        .ok()
        .and_then(|value| value.as_string().map(str::to_owned))
        .unwrap_or_else(|| "iPhone".into());
    Ok(DeviceInfo {
        name,
        version,
        id: d.device_id,
        udid: d.udid,
        connection_type: "USB".into(),
    })
}

#[tauri::command]
pub async fn list_devices() -> Result<Vec<Result<DeviceInfo, AppError>>, AppError> {
    let mut connection = get_usbmuxd().await?;
    let devices = enumerate_usb(&mut connection).await?;
    let address = usb_address()?;
    let descriptions = wired_devices(devices).map(|device| {
        let address = address.clone();
        async move {
            tokio::time::timeout(USB_TIMEOUT, describe_device(device, address))
                .await
                .unwrap_or_else(|_| {
                    Err(AppError::DeviceComs(
                        "USB device information timed out".into(),
                    ))
                })
        }
    });
    Ok(futures::future::join_all(descriptions).await)
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
    let pairing = tokio::select! {
        _ = attempt.token.cancelled() => return Err(AppError::Canceled("Association de l’iPhone".into())),
        result = tokio::time::timeout(TRUST_TIMEOUT, pairing_file(&app, &device, &mut usbmuxd, attempt.token.clone())) =>
            result.map_err(|_| AppError::LockdownPairing("Pairing timed out".into(), String::new()))??,
    };
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
    tokio::time::timeout(USB_TIMEOUT, UsbmuxdConnection::default())
        .await
        .map_err(|_| AppError::Usbmuxd("USB connection timed out".into(), String::new()))?
        .map_err(|e| AppError::Usbmuxd("Failed to connect to usbmuxd".into(), e.to_string()))
}

pub async fn get_provider(device_info: &DeviceInfo) -> Result<UsbmuxdProvider, AppError> {
    get_provider_from_connection(device_info, &mut (get_usbmuxd().await?)).await
}

pub async fn get_provider_from_connection(
    device_info: &DeviceInfo,
    connection: &mut UsbmuxdConnection,
) -> Result<UsbmuxdProvider, AppError> {
    let device = wired_devices(enumerate_usb(connection).await?)
        .find(|device| device.udid == device_info.udid)
        .ok_or_else(|| AppError::DeviceComs("Selected iPhone is no longer on USB".into()))?;
    Ok(device.to_provider(usb_address()?, "iloader"))
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
    fn usb_resolution_ignores_wireless_twins_and_preserves_distinct_phones() {
        let row = |device_id, udid: &str, connection_type| UsbmuxdDevice {
            device_id,
            udid: udid.into(),
            connection_type,
        };
        let wireless = Connection::Network("127.0.0.1".parse().unwrap());
        let rows = vec![
            row(1, "A", wireless.clone()),
            row(2, "B", wireless),
            row(3, "A", Connection::Usb),
            row(4, "C", Connection::Usb),
            row(5, "A", Connection::Usb),
        ];
        assert_eq!(
            wired_devices(rows).map(|d| d.device_id).collect::<Vec<_>>(),
            vec![3, 4]
        );
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
