//! A bounded bootstrap for the official AltStore manager. Nanashi itself is
//! installed by AltStore after the user finishes its native authentication.

use std::{
    fs::File,
    io::{Cursor, Read, Write},
    path::{Path, PathBuf},
    sync::atomic::{AtomicBool, Ordering},
    time::Duration,
};

use idevice::{IdeviceService, installation_proxy::InstallationProxyClient};
use isideload::{dev::devices::DevicesApi, sideload::application::SpecialApp};
use serde::Serialize;
use sha2::{Digest, Sha256};
use tauri::{State, Window};
use tokio::io::AsyncWriteExt;
use zip::{ZipArchive, ZipWriter, write::SimpleFileOptions};

use crate::{
    device::{DeviceInfoMutex, DeviceInfoWithPairing, get_provider},
    error::AppError,
    operation::Operation,
    pairing::place_file,
    sideload::{SideloaderGuard, SideloaderMutex},
};

const MANAGER_VERSION: &str = "2.3.3";
const MANAGER_BUILD: &str = "75";
const MANAGER_BUNDLE: &str = "com.rileytestut.AltStore";
const MANAGER_URL: &str = "https://cdn.altstore.io/file/altstore/apps/altstore/2_3_3.ipa";
const MANAGER_SIZE: u64 = 40_615_381;
const MANAGER_SHA256: &str = "3bcfc4ef816abf1551ab31304040d8d556382657663e1f0b720d1a505ca8aca9";
const MANAGER_INFO_PATH: &str = "Payload/AltStore.app/Info.plist";
const MANAGER_PAIRING_PATH: &str = "ALTPairingFile.plist";
const NANASHI_IPA: &str =
    "https://github.com/mkinvest57/nanashi/releases/download/v12.1.1/Nanashi-ios-v12.1.1.ipa";
const TEAM_TIMEOUT: Duration = Duration::from_secs(60);
const INSTALL_TIMEOUT: Duration = Duration::from_secs(8 * 60);
const PAIRING_TIMEOUT: Duration = Duration::from_secs(60);

fn uncertain_installation() -> AppError {
    AppError::InstallationUncertain(
        "L’ordinateur a cessé d’attendre. L’iPhone peut encore terminer l’installation et son association n’est pas confirmée. Ne supprimez aucune app. Vérifiez AltStore sur l’iPhone avant de relancer la préparation. Aucun nouvel essai automatique n’est lancé.".into(),
    )
}

async fn bounded_operation<T>(
    duration: Duration,
    operation: impl std::future::Future<Output = Result<T, AppError>>,
    timeout_error: AppError,
) -> Result<T, AppError> {
    // The pinned SDK uses awaited futures for transfer/installation, not a
    // detached task. Expiry drops local I/O before returning. iOS may already
    // have accepted the install command: expiry never implies rollback.
    tokio::time::timeout(duration, operation)
        .await
        .map_err(|_| timeout_error)?
}

static EXCLUSIVE_OPERATION: AtomicBool = AtomicBool::new(false);

/// Serializes authentication/account mutations and bootstrap installation.
/// The guard owns no credentials and is released on every error path.
pub struct ExclusiveOperationGuard;

pub fn begin_exclusive_operation() -> Result<ExclusiveOperationGuard, AppError> {
    EXCLUSIVE_OPERATION
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .map(|_| ExclusiveOperationGuard)
        .map_err(|_| {
            AppError::Misc(
                "Une connexion ou une installation est déjà en cours. Attendez sa fin.".into(),
            )
        })
}

impl Drop for ExclusiveOperationGuard {
    fn drop(&mut self) {
        EXCLUSIVE_OPERATION.store(false, Ordering::Release);
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BootstrapConfiguration {
    manager: &'static str,
    manager_version: &'static str,
    minimum_ios: &'static str,
    manager_download_url: &'static str,
    manager_sha256: &'static str,
    nanashi_install_url: String,
}

#[tauri::command]
pub fn nanashi_bootstrap_configuration() -> BootstrapConfiguration {
    BootstrapConfiguration {
        manager: "AltStore Classic",
        manager_version: MANAGER_VERSION,
        minimum_ios: "17.4",
        manager_download_url: MANAGER_URL,
        manager_sha256: MANAGER_SHA256,
        nanashi_install_url: nanashi_install_url(),
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BootstrapResult {
    manager: &'static str,
    manager_version: &'static str,
    manager_bundle_identifier: String,
    device_name: String,
    pairing_placed: bool,
    nanashi_installed: bool,
    next_step: &'static str,
    nanashi_install_url: String,
}

fn nanashi_install_url() -> String {
    let mut url = reqwest::Url::parse("altstore-classic://install").expect("constant URL");
    url.query_pairs_mut().append_pair("url", NANASHI_IPA);
    url.to_string()
}

fn supports_remote_altstore(version: &str) -> bool {
    let mut parts = version.split('.');
    let Some(major) = parts.next().and_then(|v| v.parse::<u32>().ok()) else {
        return false;
    };
    let Some(minor) = parts.next().and_then(|v| v.parse::<u32>().ok()) else {
        return false;
    };
    // Reject malformed values instead of guessing whether this is a supported OS.
    if parts.any(|v| v.is_empty() || v.parse::<u32>().is_err()) {
        return false;
    }
    (major, minor) >= (17, 4)
}

fn verify_fingerprint(
    size: u64,
    digest: &str,
    expected_size: u64,
    expected_digest: &str,
) -> Result<(), AppError> {
    if size != expected_size || digest != expected_digest {
        return Err(AppError::Download("Le téléchargement ne correspond pas à la version vérifiée. Rien n’a été installé. Réessayez plus tard.".into()));
    }
    Ok(())
}

async fn download_manager(path: &Path) -> Result<(), AppError> {
    let client = reqwest::Client::builder()
        .https_only(true)
        .redirect(reqwest::redirect::Policy::limited(3))
        .connect_timeout(Duration::from_secs(15))
        .timeout(Duration::from_secs(180))
        .user_agent("Mozilla/5.0 NanashiInstaller/0.1.0")
        .build()
        .map_err(|_| {
            AppError::Download("Impossible de préparer le téléchargement sécurisé.".into())
        })?;
    let mut response = client
        .get(MANAGER_URL)
        .send()
        .await
        .map_err(|_| {
            AppError::Download(
                "Impossible de télécharger AltStore. Vérifiez Internet, puis réessayez.".into(),
            )
        })?
        .error_for_status()
        .map_err(|e| {
            AppError::Download(format!(
                "Le serveur officiel a renvoyé une erreur HTTP {}.",
                e.status().map(|s| s.as_u16()).unwrap_or(0)
            ))
        })?;
    if response
        .content_length()
        .is_some_and(|size| size != MANAGER_SIZE)
    {
        return Err(AppError::Download(
            "La taille du téléchargement est inattendue. Rien n’a été installé.".into(),
        ));
    }
    let mut file = tokio::fs::File::create(path).await.map_err(|_| {
        AppError::Filesystem(
            "Impossible de préparer le téléchargement".into(),
            "Vérifiez l’espace disponible sur l’ordinateur.".into(),
        )
    })?;
    let mut hasher = Sha256::new();
    let mut size = 0_u64;
    while let Some(chunk) = response.chunk().await.map_err(|_| {
        AppError::Download("Le téléchargement a été interrompu. Rien n’a été installé.".into())
    })? {
        size = size
            .checked_add(chunk.len() as u64)
            .filter(|s| *s <= MANAGER_SIZE)
            .ok_or_else(|| {
                AppError::Download(
                    "Le téléchargement dépasse la taille vérifiée. Rien n’a été installé.".into(),
                )
            })?;
        hasher.update(&chunk);
        file.write_all(&chunk).await.map_err(|_| {
            AppError::Filesystem(
                "Impossible d’enregistrer le téléchargement".into(),
                "Vérifiez l’espace disponible sur l’ordinateur.".into(),
            )
        })?;
    }
    file.flush().await.map_err(|_| {
        AppError::Filesystem(
            "Impossible de terminer le téléchargement".into(),
            "Vérifiez l’espace disponible sur l’ordinateur.".into(),
        )
    })?;
    verify_fingerprint(
        size,
        &format!("{:x}", hasher.finalize()),
        MANAGER_SIZE,
        MANAGER_SHA256,
    )
}

fn prepared_info(bytes: &[u8], udid: &str) -> Result<Vec<u8>, AppError> {
    let mut value = plist::Value::from_reader(Cursor::new(bytes)).map_err(|_| {
        AppError::Misc("Le fichier de configuration d’AltStore est illisible.".into())
    })?;
    let info = value
        .as_dictionary_mut()
        .ok_or_else(|| AppError::Misc("La configuration d’AltStore est invalide.".into()))?;
    for (key, expected) in [
        ("CFBundleIdentifier", MANAGER_BUNDLE),
        ("CFBundleShortVersionString", MANAGER_VERSION),
        ("CFBundleVersion", MANAGER_BUILD),
        ("MinimumOSVersion", "17.4"),
    ] {
        if info.get(key).and_then(plist::Value::as_string) != Some(expected) {
            return Err(AppError::Misc(
                "La configuration d’AltStore ne correspond pas à la version vérifiée.".into(),
            ));
        }
    }
    // AltStore 2.3.3 reads the uppercase ID spelling. isideload 0.5.2 adds
    // ALTDeviceId instead; supplying the supported key before signing preserves it.
    info.insert("ALTDeviceID".into(), plist::Value::String(udid.into()));
    let mut output = Vec::new();
    value.to_writer_xml(&mut output).map_err(|_| {
        AppError::Misc("Impossible de préparer la configuration d’AltStore.".into())
    })?;
    Ok(output)
}

fn prepare_manager(source: PathBuf, target: PathBuf, udid: String) -> Result<(), AppError> {
    let fail = || AppError::Misc("Impossible de préparer AltStore. Rien n’a été installé.".into());
    let mut archive =
        ZipArchive::new(File::open(source).map_err(|_| fail())?).map_err(|_| fail())?;
    let mut writer = ZipWriter::new(File::create(target).map_err(|_| fail())?);
    let mut matched = false;
    for index in 0..archive.len() {
        let mut entry = archive.by_index(index).map_err(|_| fail())?;
        if entry.name() == MANAGER_INFO_PATH {
            if matched || entry.size() > 1_048_576 {
                return Err(fail());
            }
            let mut bytes = Vec::new();
            entry.read_to_end(&mut bytes).map_err(|_| fail())?;
            let prepared = prepared_info(&bytes, &udid)?;
            writer
                .start_file(
                    MANAGER_INFO_PATH,
                    SimpleFileOptions::default()
                        .compression_method(zip::CompressionMethod::Deflated)
                        .unix_permissions(0o644),
                )
                .map_err(|_| fail())?;
            writer.write_all(&prepared).map_err(|_| fail())?;
            matched = true;
        } else {
            writer.raw_copy_file(entry).map_err(|_| fail())?;
        }
    }
    if !matched {
        return Err(fail());
    }
    writer.finish().map_err(|_| fail())?;
    Ok(())
}

fn selected_device(state: &DeviceInfoMutex) -> Result<DeviceInfoWithPairing, AppError> {
    state
        .lock()
        .map_err(|_| AppError::Misc("Impossible d’accéder à l’iPhone sélectionné.".into()))?
        .clone()
        .ok_or(AppError::NoDeviceSelected)
}

fn extract_manager_for_signing(source: &Path, destination: &Path) -> Result<PathBuf, AppError> {
    let fail = || {
        AppError::InstallationFailed(
            "Impossible de préparer le dossier privé de signature. Code : INSTALL-ARCHIVE.".into(),
        )
    };
    let mut archive =
        ZipArchive::new(File::open(source).map_err(|_| fail())?).map_err(|_| fail())?;
    for index in 0..archive.len() {
        let entry = archive.by_index(index).map_err(|_| fail())?;
        if entry.enclosed_name().is_none() || entry.is_symlink() {
            return Err(fail());
        }
    }
    archive.extract(destination).map_err(|_| fail())?;
    let bundle = destination.join("Payload/AltStore.app");
    if !bundle.join("Info.plist").is_file() {
        return Err(fail());
    }
    Ok(bundle)
}

fn ensure_same_device(
    state: &DeviceInfoMutex,
    expected: &DeviceInfoWithPairing,
) -> Result<(), AppError> {
    let current = selected_device(state)?;
    if current.info.udid != expected.info.udid || current.pairing != expected.pairing {
        return Err(AppError::DeviceComs(
            "L’iPhone sélectionné a changé. Choisissez le bon appareil, puis recommencez.".into(),
        ));
    }
    Ok(())
}

fn expected_manager_identifier(team: &str) -> Result<String, AppError> {
    if team.len() != 10
        || !team
            .bytes()
            .all(|v| v.is_ascii_uppercase() || v.is_ascii_digit())
    {
        return Err(AppError::Auth(
            "Apple a renvoyé un identifiant de signature invalide.".into(),
        ));
    }
    Ok(format!("{MANAGER_BUNDLE}.{team}"))
}

fn is_expected_manager(key: &str, info: &plist::Value, expected: &str) -> bool {
    let Some(info) = info.as_dictionary() else {
        return false;
    };
    key == expected
        && [
            ("CFBundleIdentifier", expected),
            ("CFBundleShortVersionString", MANAGER_VERSION),
            ("CFBundleVersion", MANAGER_BUILD),
        ]
        .iter()
        .all(|(field, value)| info.get(*field).and_then(plist::Value::as_string) == Some(*value))
}

#[tauri::command]
pub async fn install_nanashi_manager_operation(
    window: Window,
    device_state: State<'_, DeviceInfoMutex>,
    sideloader_state: State<'_, SideloaderMutex>,
) -> Result<BootstrapResult, AppError> {
    let _exclusive = begin_exclusive_operation()?;
    let op = Operation::new("install_nanashi_manager".into(), &window);
    op.start("preflight")?;
    let device = op.fail_if_err("preflight", selected_device(&device_state))?;
    if !supports_remote_altstore(&device.info.version) {
        return op.fail(
            "preflight",
            AppError::DeviceComs(
                "Cet installateur nécessite iOS 17.4 ou plus récent. Vos apps actuelles n’ont pas été modifiées."
                    .into(),
            ),
        );
    }
    // Hold the authenticated sideloader throughout the operation. Never re-read
    // a mutable selected account or device after an awaited network request.
    let mut sideloader = op.fail_if_err("preflight", SideloaderGuard::take(&sideloader_state))?;
    let team = op.fail_if_err(
        "preflight",
        bounded_operation(
            TEAM_TIMEOUT,
            async {
                sideloader
                    .get_mut()
                    .get_team()
                    .await
                    .map_err(crate::account::safe_auth_error)
            },
            AppError::Developer("Apple n’a pas répondu à temps à la vérification du compte. L’installation n’a pas été lancée. Aucun nouvel essai automatique n’est lancé.".into()),
        ).await,
    )?;
    let expected_bundle =
        op.fail_if_err("preflight", expected_manager_identifier(&team.team_id))?;
    if let Some(proof) = sideloader.existing_signing() {
        op.fail_if_err("preflight", bounded_operation(
            TEAM_TIMEOUT,
            crate::existing_signing::revalidate_existing_signing(
                sideloader.get_mut().get_dev_session(), &team, &proof),
            AppError::ExistingSignature("La vérification du certificat a dépassé le délai. Aucun certificat n’a été modifié. Code : EXISTING-NETWORK.".into()),
        ).await)?;
    }
    op.fail_if_err("preflight", get_provider(&device.info).await)?;
    let temp = op.fail_if_err(
        "preflight",
        tempfile::Builder::new()
            .prefix("nanashi-installer-")
            .tempdir()
            .map_err(|_| {
                AppError::Filesystem(
                    "Impossible de préparer un dossier temporaire privé".into(),
                    "Vérifiez l’espace disponible sur l’ordinateur.".into(),
                )
            }),
    )?;
    let downloaded = temp.path().join("official.ipa");
    let prepared = temp.path().join("prepared.ipa");
    op.move_on("preflight", "download")?;
    op.fail_if_err("download", download_manager(&downloaded).await)?;
    op.move_on("download", "prepare")?;
    let target = prepared.clone();
    let signing_directory = temp.path().join("signing");
    let udid = device.info.udid.clone();
    let prepared_bundle = op.fail_if_err(
        "prepare",
        tokio::task::spawn_blocking(move || {
            prepare_manager(downloaded, target.clone(), udid)?;
            // Passing a directory avoids the SDK's shared *_extracted path.
            // The parent TempDir also removes encrypted signing material on
            // failure or cancellation, not just after successful installation.
            extract_manager_for_signing(&target, &signing_directory)
        })
        .await
        .map_err(|_| {
            AppError::Misc(
                "La préparation d’AltStore a été interrompue. Rien n’a été installé.".into(),
            )
        })
        .and_then(|result| result),
    )?;
    op.fail_if_err("prepare", ensure_same_device(&device_state, &device))?;
    // Resolve this UDID again after downloading; never reuse a USB device slot
    // that may have changed while the phone was unplugged.
    let provider = op.fail_if_err("prepare", get_provider(&device.info).await)?;
    op.move_on("prepare", "install")?;
    // The pinned engine embeds the existing signing certificate. Its legacy
    // encrypted pairing format is not used by this release; place the supported
    // Documents file below instead. The encrypted signing identity is embedded
    // for AltStore; the Apple account password is never transferred to the phone.
    let installed = op.fail_if_err(
        "install",
        bounded_operation(
            INSTALL_TIMEOUT,
            async {
                if let Some(proof) = sideloader.existing_signing() {
                    let info = isideload::util::device::IdeviceInfo::from_device(&provider)
                        .await
                        .map_err(crate::error::safe_installation_error)?;
                    if info.udid != device.info.udid {
                        return Err(AppError::DeviceComs(
                            "L’iPhone connecté a changé. L’installation est arrêtée.".into(),
                        ));
                    }
                    sideloader
                        .get_mut()
                        .get_dev_session()
                        .ensure_device_registered(&team, &info.name, &info.udid, None)
                        .await
                        .map_err(crate::error::safe_installation_error)?;
                    let (signed_path, special) = sideloader
                        .get_mut()
                        .sign_app(
                            prepared_bundle,
                            Some(team.clone()),
                            true,
                            None::<fn(f32) -> std::future::Ready<()>>,
                            None,
                            Some(&info.udid),
                        )
                        .await
                        .map_err(crate::error::safe_installation_error)?;
                    if special != Some(SpecialApp::AltStore) {
                        return Err(AppError::InstallationFailed(
                            "L’archive signée n’est pas AltStore. Code : INSTALL-ARCHIVE.".into(),
                        ));
                    }
                    // Match AltStore's OpenSSL import before transferring the
                    // package. A bad embedded identity must never invite its
                    // certificate-replacement fallback on the phone.
                    crate::existing_signing::verify_embedded_identity(&signed_path, &proof)?;
                    ensure_same_device(&device_state, &device)?;
                    isideload::sideload::install::install_app(&provider, &signed_path, |_| {})
                        .await
                        .map_err(crate::error::safe_installation_error)?;
                    Ok(special)
                } else {
                    sideloader
                        .get_mut()
                        .install_app(
                            &provider,
                            prepared_bundle,
                            true,
                            None::<fn(f32) -> std::future::Ready<()>>,
                            None,
                        )
                        .await
                        .map_err(crate::error::safe_installation_error)
                }
            },
            uncertain_installation(),
        )
        .await,
    )?;
    if installed != Some(SpecialApp::AltStore) {
        return op.fail(
            "install",
            AppError::Misc(
                "Le moteur de signature n’a pas reconnu AltStore. La configuration a été arrêtée."
                    .into(),
            ),
        );
    }
    op.move_on("install", "pairing")?;
    let pairing_result = async {
        ensure_same_device(&device_state, &device)?;
        let mut proxy = InstallationProxyClient::connect(&provider).await
            .map_err(|_| AppError::DeviceComs("AltStore a été installé, mais l’iPhone n’a pas confirmé son identité. Gardez l’iPhone déverrouillé, puis réessayez.".into()))?;
        let apps = proxy.get_apps(Some("User"), Some(vec![expected_bundle.clone()])).await
            .map_err(|_| AppError::DeviceComs("AltStore a été installé, mais sa présence sur l’iPhone n’a pas pu être vérifiée.".into()))?;
        if !apps
            .iter()
            .any(|(key, info)| is_expected_manager(key, info, &expected_bundle))
        {
            return Err(AppError::DeviceComs("L’iPhone n’a pas confirmé la version d’AltStore attendue pour votre compte. L’association n’a pas été transférée.".into()));
        }
        place_file(device.pairing.clone(), &provider, expected_bundle.clone(), MANAGER_PAIRING_PATH.into())
            .await.map_err(|_| AppError::DeviceComs("AltStore a été installé, mais l’association n’a pas pu être transférée. Gardez l’iPhone déverrouillé et réessayez. Ne supprimez pas vos apps.".into()))
    };
    op.fail_if_err(
        "pairing",
        bounded_operation(PAIRING_TIMEOUT, pairing_result, uncertain_installation()).await,
    )?;
    op.complete("pairing")?;
    Ok(BootstrapResult {
        manager: "AltStore Classic",
        manager_version: MANAGER_VERSION,
        manager_bundle_identifier: expected_bundle,
        device_name: device.info.name,
        pairing_placed: true,
        nanashi_installed: false,
        next_step: "finish_on_iphone",
        nanashi_install_url: nanashi_install_url(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn stalled_operation_is_dropped_before_returning_an_uncertain_result() {
        use std::sync::{Arc, atomic::AtomicUsize};
        struct DropSignal(Arc<AtomicBool>);
        impl Drop for DropSignal {
            fn drop(&mut self) {
                self.0.store(true, Ordering::SeqCst);
            }
        }
        let dropped = Arc::new(AtomicBool::new(false));
        let attempts = Arc::new(AtomicUsize::new(0));
        let resource = DropSignal(dropped.clone());
        let entered = attempts.clone();
        let stalled = async move {
            let _resource = resource;
            entered.fetch_add(1, Ordering::SeqCst);
            std::future::pending::<Result<(), AppError>>().await
        };
        let result =
            bounded_operation(Duration::from_millis(1), stalled, uncertain_installation()).await;
        assert!(dropped.load(Ordering::SeqCst));
        assert_eq!(attempts.load(Ordering::SeqCst), 1);
        let error = result.unwrap_err();
        assert!(matches!(error, AppError::InstallationUncertain(_)));
        assert_eq!(
            serde_json::to_value(error).unwrap()["type"],
            "installation_uncertain"
        );
    }

    #[tokio::test]
    async fn bounded_operation_preserves_success_and_explicit_failures() {
        let success = bounded_operation(
            Duration::from_secs(1),
            async { Ok(75) },
            uncertain_installation(),
        )
        .await;
        assert_eq!(success.unwrap(), 75);
        let failure = bounded_operation(
            Duration::from_secs(1),
            async { Err::<(), _>(AppError::MaxApps("limit".into())) },
            uncertain_installation(),
        )
        .await;
        assert!(matches!(failure, Err(AppError::MaxApps(_))));
    }

    #[test]
    fn accepts_only_supported_numeric_ios_versions() {
        for version in ["17.4", "17.4.1", "18.0", "27.0.1"] {
            assert!(supports_remote_altstore(version), "{version}")
        }
        for version in [
            "16.7.12", "17.3.9", "", "27", "iOS 27.0", "27.bad", "17.4.", "17.4beta",
        ] {
            assert!(!supports_remote_altstore(version), "{version}")
        }
    }

    #[test]
    fn rejects_truncation_wrong_digest_and_oversized_artifacts() {
        let digest = format!("{:x}", Sha256::digest(b"abc"));
        assert!(
            verify_fingerprint(
                3,
                &digest,
                3,
                "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
            )
            .is_ok()
        );
        assert!(verify_fingerprint(2, &digest, 3, &digest).is_err());
        assert!(verify_fingerprint(4, &digest, 3, &digest).is_err());
        assert!(verify_fingerprint(3, "different", 3, &digest).is_err());
    }

    fn official_info() -> plist::Value {
        let mut info = plist::Dictionary::new();
        info.insert("CFBundleIdentifier".into(), MANAGER_BUNDLE.into());
        info.insert("CFBundleShortVersionString".into(), MANAGER_VERSION.into());
        info.insert("CFBundleVersion".into(), MANAGER_BUILD.into());
        info.insert("MinimumOSVersion".into(), "17.4".into());
        info.insert(
            "BGTaskSchedulerPermittedIdentifiers".into(),
            plist::Value::Array(vec![format!("{MANAGER_BUNDLE}.*").into()]),
        );
        plist::Value::Dictionary(info)
    }

    #[test]
    fn prepares_only_the_correct_device_key_without_changing_identity() {
        let original = official_info();
        let mut bytes = Vec::new();
        original.to_writer_xml(&mut bytes).unwrap();
        let prepared = prepared_info(&bytes, "TEST-DEVICE").unwrap();
        let mut changed = plist::Value::from_reader(Cursor::new(prepared)).unwrap();
        assert_eq!(
            changed.as_dictionary_mut().unwrap().remove("ALTDeviceID"),
            Some("TEST-DEVICE".into())
        );
        assert_eq!(changed, original);
        let mut wrong = original.clone();
        wrong
            .as_dictionary_mut()
            .unwrap()
            .insert("CFBundleIdentifier".into(), "different.app".into());
        let mut bytes = Vec::new();
        wrong.to_writer_xml(&mut bytes).unwrap();
        assert!(prepared_info(&bytes, "TEST-DEVICE").is_err());
    }

    #[test]
    fn account_scoped_lookup_does_not_select_another_altstore() {
        let expected = expected_manager_identifier("A1B2C3D4E5").unwrap();
        let mut matching = official_info();
        matching
            .as_dictionary_mut()
            .unwrap()
            .insert("CFBundleIdentifier".into(), expected.clone().into());
        assert!(is_expected_manager(&expected, &matching, &expected));
        assert!(!is_expected_manager(
            "com.rileytestut.AltStore.Z9Y8X7W6V5",
            &matching,
            &expected
        ));
        assert!(!is_expected_manager(&expected, &official_info(), &expected));
        let mut outdated = matching.clone();
        outdated
            .as_dictionary_mut()
            .unwrap()
            .insert("CFBundleShortVersionString".into(), "2.3.2".into());
        assert!(!is_expected_manager(&expected, &outdated, &expected));
        matching
            .as_dictionary_mut()
            .unwrap()
            .remove("CFBundleVersion");
        assert!(!is_expected_manager(&expected, &matching, &expected));
        assert!(expected_manager_identifier("bad/team").is_err());
    }

    #[test]
    fn prepared_archive_preserves_other_files_and_requires_official_metadata() {
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("source.ipa");
        let target = temp.path().join("prepared.ipa");
        let mut writer = ZipWriter::new(File::create(&source).unwrap());
        writer
            .start_file(MANAGER_INFO_PATH, SimpleFileOptions::default())
            .unwrap();
        let mut info = Vec::new();
        official_info().to_writer_xml(&mut info).unwrap();
        writer.write_all(&info).unwrap();
        writer
            .start_file(
                "Payload/AltStore.app/untouched",
                SimpleFileOptions::default(),
            )
            .unwrap();
        writer.write_all(b"unchanged bytes").unwrap();
        writer.finish().unwrap();
        prepare_manager(source, target.clone(), "TEST-DEVICE".into()).unwrap();
        let mut archive = ZipArchive::new(File::open(target).unwrap()).unwrap();
        assert_eq!(archive.len(), 2);
        let mut unchanged = Vec::new();
        archive
            .by_name("Payload/AltStore.app/untouched")
            .unwrap()
            .read_to_end(&mut unchanged)
            .unwrap();
        assert_eq!(unchanged, b"unchanged bytes");
        let mut info = Vec::new();
        archive
            .by_name(MANAGER_INFO_PATH)
            .unwrap()
            .read_to_end(&mut info)
            .unwrap();
        let parsed = plist::Value::from_reader(Cursor::new(info)).unwrap();
        assert_eq!(
            parsed.as_dictionary().unwrap().get("ALTDeviceID"),
            Some(&"TEST-DEVICE".into())
        );
    }

    #[test]
    fn changed_selection_or_pairing_is_not_used_for_installation() {
        let snapshot = DeviceInfoWithPairing {
            info: crate::device::DeviceInfo {
                name: "Test phone".into(),
                id: 1,
                udid: "PHONE-A".into(),
                connection_type: "USB".into(),
                version: "17.4".into(),
            },
            pairing: vec![1, 2, 3],
        };
        let state = DeviceInfoMutex::new(Some(snapshot.clone()));
        assert!(ensure_same_device(&state, &snapshot).is_ok());
        state.lock().unwrap().as_mut().unwrap().info.udid = "PHONE-B".into();
        assert!(ensure_same_device(&state, &snapshot).is_err());
        *state.lock().unwrap() = Some(snapshot.clone());
        state.lock().unwrap().as_mut().unwrap().pairing = vec![4, 5, 6];
        assert!(ensure_same_device(&state, &snapshot).is_err());
    }

    #[test]
    fn signing_bundle_stays_in_owned_temporary_directory() {
        let temp = tempfile::tempdir().unwrap();
        let archive_path = temp.path().join("prepared.ipa");
        let mut writer = ZipWriter::new(File::create(&archive_path).unwrap());
        writer
            .start_file(MANAGER_INFO_PATH, SimpleFileOptions::default())
            .unwrap();
        writer.write_all(b"test fixture").unwrap();
        writer.finish().unwrap();
        let bundle =
            extract_manager_for_signing(&archive_path, &temp.path().join("private")).unwrap();
        assert!(bundle.starts_with(temp.path()));
        assert!(bundle.join("Info.plist").exists());
        drop(temp);
        assert!(!bundle.exists());
    }

    #[test]
    fn signing_extraction_rejects_escape_paths() {
        let temp = tempfile::tempdir().unwrap();
        let archive_path = temp.path().join("invalid.ipa");
        let mut writer = ZipWriter::new(File::create(&archive_path).unwrap());
        writer
            .start_file("../outside", SimpleFileOptions::default())
            .unwrap();
        writer.write_all(b"must not escape").unwrap();
        writer.finish().unwrap();
        assert!(extract_manager_for_signing(&archive_path, &temp.path().join("private")).is_err());
        assert!(!temp.path().join("outside").exists());
    }

    #[test]
    fn account_changes_and_installation_cannot_overlap() {
        let first = begin_exclusive_operation().unwrap();
        assert!(begin_exclusive_operation().is_err());
        drop(first);
        assert!(begin_exclusive_operation().is_ok());
    }

    #[test]
    fn returned_handoff_is_pinned_and_does_not_claim_nanashi_installed() {
        let url = reqwest::Url::parse(&nanashi_install_url()).unwrap();
        assert_eq!(url.scheme(), "altstore-classic");
        assert_eq!(url.host_str(), Some("install"));
        assert_eq!(
            url.query_pairs().collect::<Vec<_>>(),
            vec![("url".into(), NANASHI_IPA.into())]
        );
        assert_eq!(MANAGER_SIZE, 40_615_381);
        assert_eq!(MANAGER_SHA256.len(), 64);
    }
}
