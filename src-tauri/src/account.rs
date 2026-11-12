use futures::FutureExt;
use isideload::{
    anisette::{
        AnisetteClientInfo, AnisetteDataResponse, AnisetteProvider,
        remote_v3::RemoteV3AnisetteProvider,
    },
    auth::apple_account::{AppleAccount, TwoFactorCallbackParams, TwoFactorCallbackResponse},
    dev::{
        app_ids::{AppIdsApi, ListAppIdsResponse},
        certificates::{CertificatesApi, DevelopmentCertificate},
        developer_session::DeveloperSession,
    },
    sideload::{
        SideloaderBuilder,
        builder::{ExtensionsBehavior, ExtensionsBehaviorSelection, MaxCertsBehavior},
        sideloader::Sideloader,
    },
    util::callbacks::{ExtensionsBehaviorCallbackBox, MaxCertsCallbackBox},
};
use keyring::Entry;
use rootcause::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    future::Future,
    sync::{Arc, Mutex},
    time::Duration,
};
use tauri::{AppHandle, Emitter, Listener, State, Window};
use tauri_plugin_store::StoreExt;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::{
    error::AppError,
    secure_storage::{KEYRING_SERVICE, create_sideloading_storage},
    sideload::{SideloaderGuard, SideloaderMutex},
};

const ANISETTE_URL: &str = "https://mac-ani.jkcoxson.com";
const LOGIN_TIMEOUT: Duration = Duration::from_secs(240);
const TWO_FACTOR_TIMEOUT: Duration = Duration::from_secs(120);
const ANISETTE_TIMEOUT: Duration = Duration::from_secs(45);
const CERTIFICATES_PRESERVED: &str = "La limite de certificats Apple est atteinte. L’installation est arrêtée : les certificats et profils existants sont conservés. Aucun certificat n’a été révoqué.";
const ANISETTE_STATE_PRESERVED: &str = "L’état de connexion enregistré est illisible. Nanashi Installer s’arrête et le conserve sans le remplacer.";
static ACTIVE_LOGIN: Mutex<Option<CancellationToken>> = Mutex::new(None);

#[derive(Debug, thiserror::Error)]
#[error("{CERTIFICATES_PRESERVED}")]
pub(crate) struct CertificatesPreserved;

#[derive(Debug, thiserror::Error)]
#[error(
    "Le service de connexion demande une réinitialisation. Nanashi Installer s’arrête et conserve l’état existant."
)]
struct AnisetteResetBlocked;

fn reject_anisette_reset(force_reset: bool) -> Result<(), rootcause::Report> {
    if force_reset {
        return Err(AnisetteResetBlocked.into());
    }
    Ok(())
}

fn validate_stored_anisette_state(bytes: &[u8]) -> Result<(), AppError> {
    let invalid = || AppError::Anisette(ANISETTE_STATE_PRESERVED.into());
    let value = plist::Value::from_reader(std::io::Cursor::new(bytes)).map_err(|_| invalid())?;
    let dictionary = value.as_dictionary().ok_or_else(invalid)?;
    if dictionary
        .get("keychain_identifier")
        .and_then(plist::Value::as_data)
        .is_none_or(|identifier| identifier.len() != 16)
        || dictionary
            .get("adi_pb")
            .is_some_and(|value| value.as_data().is_none())
    {
        return Err(invalid());
    }
    Ok(())
}

// Keep the upstream protocol, but do not silently reset an existing ADI identity.
struct PreservingAnisetteProvider(RemoteV3AnisetteProvider);

#[async_trait::async_trait]
impl AnisetteProvider for PreservingAnisetteProvider {
    async fn get_anisette_data(&self) -> Result<AnisetteDataResponse, rootcause::Report> {
        tokio::time::timeout(ANISETTE_TIMEOUT, self.0.get_anisette_data())
            .await
            .context("Anisette request timed out")?
    }

    async fn resync(&self, sim: &str) -> Result<AnisetteDataResponse, rootcause::Report> {
        tokio::time::timeout(ANISETTE_TIMEOUT, self.0.resync(sim))
            .await
            .context("Anisette synchronization timed out")?
    }

    async fn get_client_info(&self) -> Result<AnisetteClientInfo, rootcause::Report> {
        tokio::time::timeout(ANISETTE_TIMEOUT, self.0.get_client_info())
            .await
            .context("Anisette client information timed out")?
    }

    async fn provision(
        &mut self,
        gs: &Arc<isideload::auth::grandslam::GrandSlam>,
        force_reset: bool,
    ) -> Result<(), rootcause::Report> {
        reject_anisette_reset(force_reset)?;
        tokio::time::timeout(ANISETTE_TIMEOUT, self.0.provision(gs, false))
            .await
            .context("Anisette provisioning timed out")?
    }
}

struct LoginAttempt(CancellationToken);

impl LoginAttempt {
    fn begin() -> Self {
        let token = CancellationToken::new();
        *ACTIVE_LOGIN.lock().unwrap() = Some(token.clone());
        Self(token)
    }
}

impl Drop for LoginAttempt {
    fn drop(&mut self) {
        self.0.cancel();
        *ACTIVE_LOGIN.lock().unwrap() = None;
    }
}

// Unregister even if the outer login is cancelled, times out or drops its future.
struct TwoFactorListener {
    window: Window,
    event_id: tauri::EventId,
}

impl Drop for TwoFactorListener {
    fn drop(&mut self) {
        self.window.unlisten(self.event_id);
    }
}

#[tauri::command]
pub fn cancel_login() {
    if let Some(token) = ACTIVE_LOGIN.lock().unwrap().as_ref() {
        token.cancel();
    }
}

fn validated_anisette_url(input: &str) -> Result<&'static str, AppError> {
    let url = reqwest::Url::parse(input.trim())
        .map_err(|_| AppError::Anisette("Adresse du service de connexion invalide.".into()))?;
    if url.scheme() != "https"
        || url.host_str() != Some("mac-ani.jkcoxson.com")
        || !url.username().is_empty()
        || url.password().is_some()
        || url.port().is_some_and(|port| port != 443)
        || url.path() != "/"
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(AppError::Anisette(
            "Ce service de connexion n’est pas autorisé par Nanashi Installer.".into(),
        ));
    }
    Ok(ANISETTE_URL)
}

fn two_factor_code(payload: &str) -> Result<String, AppError> {
    let code = serde_json::from_str::<String>(payload)
        .map_err(|_| AppError::Auth("Le code Apple doit contenir six chiffres.".into()))?;
    let code = code.trim();
    if code.len() != 6 || !code.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(AppError::Auth(
            "Le code Apple doit contenir six chiffres.".into(),
        ));
    }
    Ok(code.to_owned())
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct TwoFactorChallenge {
    request_id: String,
    unknown: bool,
    sms: bool,
    numbers: Vec<MaskedPhoneNumber>,
    selected_number_id: Option<u32>,
    has_error: bool,
}

#[derive(Clone, Serialize)]
struct MaskedPhoneNumber {
    id: u32,
    label: String,
}

impl TwoFactorChallenge {
    fn new(params: &TwoFactorCallbackParams) -> Self {
        Self {
            request_id: uuid::Uuid::new_v4().to_string(),
            unknown: params.unknown,
            sms: params.sms,
            numbers: params
                .numbers
                .iter()
                .map(|number| {
                    // Never expose the full trusted number, even if the provider supplies it.
                    let suffix: String = number
                        .last_two_digits
                        .chars()
                        .filter(char::is_ascii_digit)
                        .collect::<Vec<_>>()
                        .into_iter()
                        .rev()
                        .take(2)
                        .collect::<Vec<_>>()
                        .into_iter()
                        .rev()
                        .collect();
                    MaskedPhoneNumber {
                        id: number.id,
                        label: format!("••••{suffix}"),
                    }
                })
                .collect(),
            selected_number_id: params.selected_number_id,
            has_error: params.last_error.is_some(),
        }
    }
}

#[derive(Deserialize)]
#[serde(tag = "action", rename_all = "kebab-case", deny_unknown_fields)]
enum TwoFactorAction {
    SubmitCode {
        #[serde(rename = "requestId")]
        request_id: String,
        code: String,
    },
    RequestDeviceCode {
        #[serde(rename = "requestId")]
        request_id: String,
    },
    RequestSmsCode {
        #[serde(rename = "requestId")]
        request_id: String,
        #[serde(rename = "phoneId")]
        phone_id: u32,
    },
}

fn two_factor_response(
    payload: &str,
    challenge: &TwoFactorChallenge,
) -> Result<TwoFactorCallbackResponse, AppError> {
    if payload.trim_start().starts_with('"') && !challenge.unknown {
        return two_factor_code(payload).map(TwoFactorCallbackResponse::SubmitCode);
    }
    let action = serde_json::from_str::<TwoFactorAction>(payload)
        .map_err(|_| AppError::Auth("La réponse de vérification Apple est invalide.".into()))?;
    let request_id = match &action {
        TwoFactorAction::SubmitCode { request_id, .. }
        | TwoFactorAction::RequestDeviceCode { request_id }
        | TwoFactorAction::RequestSmsCode { request_id, .. } => request_id,
    };
    if request_id != &challenge.request_id {
        return Err(AppError::Auth(
            "Cette demande de vérification Apple a expiré.".into(),
        ));
    }
    match action {
        TwoFactorAction::SubmitCode { code, .. } if !challenge.unknown => {
            two_factor_code(&serde_json::to_string(&code).unwrap())
                .map(TwoFactorCallbackResponse::SubmitCode)
        }
        TwoFactorAction::RequestDeviceCode { .. } => Ok(TwoFactorCallbackResponse::SendToDevices),
        TwoFactorAction::RequestSmsCode { phone_id, .. }
            if challenge.numbers.iter().any(|number| number.id == phone_id) =>
        {
            Ok(TwoFactorCallbackResponse::SendSms(phone_id))
        }
        _ => Err(AppError::Auth(
            "Choisissez une méthode de vérification proposée par Apple.".into(),
        )),
    }
}

async fn bounded_auth<T>(
    future: impl Future<Output = Result<T, AppError>>,
    cancellation: CancellationToken,
    timeout: Duration,
) -> Result<T, AppError> {
    tokio::select! {
        biased;
        _ = cancellation.cancelled() => Err(AppError::Canceled("Connexion Apple".into())),
        result = tokio::time::timeout(timeout, future) => result.map_err(|_| {
            AppError::Auth("Le délai de connexion Apple est dépassé. Aucune nouvelle tentative automatique n’a été lancée.".into())
        })?,
    }
}

async fn wait_for_two_factor_response(
    mut receiver: mpsc::Receiver<String>,
    cancellation: CancellationToken,
    challenge: &TwoFactorChallenge,
) -> Result<TwoFactorCallbackResponse, AppError> {
    bounded_auth(
        async move {
            let payload = receiver
                .recv()
                .await
                .ok_or_else(|| AppError::Canceled("Vérification Apple".into()))?;
            two_factor_response(&payload, challenge)
        },
        cancellation,
        TWO_FACTOR_TIMEOUT,
    )
    .await
}

// Do not forward raw authentication responses, headers or server bodies to UI/logs.
pub(crate) fn safe_auth_error(report: rootcause::Report) -> AppError {
    for cause in report.iter_reports() {
        if cause
            .downcast_current_context::<CertificatesPreserved>()
            .is_some()
        {
            return AppError::Developer(CERTIFICATES_PRESERVED.into());
        }
        if cause
            .downcast_current_context::<AnisetteResetBlocked>()
            .is_some()
        {
            return AppError::Anisette(AnisetteResetBlocked.to_string());
        }
        if let Some(error) = cause.downcast_current_context::<isideload::SideloadError>() {
            match error {
                isideload::SideloadError::AuthWithMessage(code, _) => {
                    return AppError::Auth(format!(
                        "Apple a refusé la connexion ({code}). Aucun nouvel essai automatique n’a été lancé."
                    ));
                }
                isideload::SideloadError::DeveloperError(code, _) => {
                    return AppError::Developer(format!(
                        "Le service développeur Apple a refusé la demande ({code})."
                    ));
                }
                _ => {}
            }
        }
    }
    AppError::Auth("La connexion Apple n’a pas abouti. Vérifiez votre connexion et le code de validation, puis réessayez manuellement.".into())
}

fn blocked_certificate_selection() -> Result<Option<Vec<String>>, rootcause::Report> {
    Err(CertificatesPreserved)
        .context("Existing development certificates are preserved")
        .map_err(Into::into)
}

#[tauri::command]
pub async fn login_new(
    handle: AppHandle,
    window: Window,
    sideloader_state: State<'_, SideloaderMutex>,
    email: String,
    password: String,
    anisette_server: String,
    save_credentials: bool,
) -> Result<(), AppError> {
    let _operation = crate::nanashi::begin_exclusive_operation()?;
    let account = login(&handle, window, &email, &password, anisette_server).await?;

    if save_credentials {
        let pass_entry = Entry::new(KEYRING_SERVICE, &email).map_err(|e| {
            AppError::KeyringWithMessage(
                "Failed to create entry for credentials".into(),
                e.to_string(),
            )
        })?;
        pass_entry.set_password(&password).map_err(|e| {
            AppError::KeyringWithMessage("Failed to save credentials".into(), e.to_string())
        })?;
        let store = handle
            .store("data.json")
            .map_err(|e| AppError::Misc(format!("Failed to get store: {:?}", e)))?;
        let mut existing_ids = store
            .get("ids")
            .unwrap_or_else(|| Value::Array(vec![]))
            .as_array()
            .cloned()
            .unwrap_or_else(std::vec::Vec::new);
        let value = Value::String(email.clone());
        if !existing_ids.contains(&value) {
            existing_ids.push(value);
        }
        store.set("ids", Value::Array(existing_ids));
    }
    *sideloader_state.lock().unwrap() = Some(account);
    Ok(())
}

#[tauri::command]
pub async fn login_stored(
    handle: AppHandle,
    window: Window,
    email: String,
    anisette_server: String,
    sideloader_state: State<'_, SideloaderMutex>,
) -> Result<(), AppError> {
    let _operation = crate::nanashi::begin_exclusive_operation()?;
    // Validate before retrieving credentials or starting any remote operation.
    validated_anisette_url(&anisette_server)?;
    let pass_entry = Entry::new(KEYRING_SERVICE, &email).map_err(|e| {
        AppError::KeyringWithMessage(
            "Failed to create keyring entry for credentials".to_string(),
            e.to_string(),
        )
    })?;
    let password = pass_entry.get_password().map_err(|e| {
        AppError::KeyringWithMessage("Failed to get credentials".to_string(), e.to_string())
    })?;
    let account = login(&handle, window, &email, &password, anisette_server).await?;
    let mut sideloader_guard = sideloader_state.lock().unwrap();
    *sideloader_guard = Some(account);

    Ok(())
}

#[tauri::command]
pub fn delete_account(handle: AppHandle, email: String) -> Result<(), AppError> {
    let _operation = crate::nanashi::begin_exclusive_operation()?;
    let store = handle
        .store("data.json")
        .map_err(|e| AppError::Misc(format!("Failed to get store: {:?}", e)))?;
    let mut existing_ids = store
        .get("ids")
        .unwrap_or_else(|| Value::Array(vec![]))
        .as_array()
        .cloned()
        .unwrap_or_else(std::vec::Vec::new);
    existing_ids.retain(|v| v.as_str().is_none_or(|s| s != email));
    store.set("ids", Value::Array(existing_ids));
    let pass_entry = Entry::new(KEYRING_SERVICE, &email).map_err(|e| {
        AppError::KeyringWithMessage(
            "Failed to create keyring entry for credentials".into(),
            e.to_string(),
        )
    })?;
    pass_entry.delete_credential().map_err(|e| {
        AppError::KeyringWithMessage("Failed to delete credentials".into(), e.to_string())
    })?;
    Ok(())
}

#[tauri::command]
pub fn logged_in_as(sideloader_state: State<'_, SideloaderMutex>) -> Option<String> {
    let sideloader_guard = sideloader_state.lock().unwrap();
    sideloader_guard
        .as_ref()
        .map(|account| account.get_email().to_string())
}

#[tauri::command]
pub fn invalidate_account(sideloader_state: State<'_, SideloaderMutex>) -> Result<(), AppError> {
    let _operation = crate::nanashi::begin_exclusive_operation()?;
    let mut sideloader_guard = sideloader_state.lock().unwrap();
    *sideloader_guard = None;
    Ok(())
}

async fn login(
    app: &AppHandle,
    window: Window,
    email: &str,
    password: &str,
    anisette_server: String,
) -> Result<Sideloader<MaxCertsCallbackBox, ExtensionsBehaviorCallbackBox>, AppError> {
    let anisette_url = validated_anisette_url(&anisette_server)?;
    // Fail closed before password authentication if secrets cannot be protected.
    let storage = create_sideloading_storage(app)?;
    let attempt = LoginAttempt::begin();
    bounded_auth(
        login_inner(
            app,
            window,
            email,
            password,
            anisette_url,
            storage,
            attempt.0.clone(),
        ),
        attempt.0.clone(),
        LOGIN_TIMEOUT,
    )
    .await
}

async fn login_inner(
    app: &AppHandle,
    window: Window,
    email: &str,
    password: &str,
    anisette_url: &str,
    storage: Box<dyn isideload::util::storage::SideloadingStorage>,
    cancellation: CancellationToken,
) -> Result<Sideloader<MaxCertsCallbackBox, ExtensionsBehaviorCallbackBox>, AppError> {
    // Upstream treats unreadable stored state as absent and has an unchecked
    // 16-byte conversion. Validate first, then load explicitly without replacing it.
    let state_data = storage.retrieve_data(
        isideload::anisette::remote_v3::ANISETTE_STATE_KEY,
    ).map_err(|_| AppError::Keyring("Impossible de lire l’état de connexion dans le trousseau. Il est conservé sans modification.".into()))?;
    if let Some(bytes) = state_data.as_ref() {
        validate_stored_anisette_state(bytes)?;
    }
    let mut remote_anisette = RemoteV3AnisetteProvider::new(anisette_url, storage, "0".to_string())
        .map_err(safe_auth_error)?;
    if let Some(bytes) = state_data {
        remote_anisette.state = Some(
            plist::from_bytes(&bytes)
                .map_err(|_| AppError::Anisette(ANISETTE_STATE_PRESERVED.into()))?,
        );
    }
    let tfa_closure = {
        let window_clone = window.clone();
        move |params: TwoFactorCallbackParams| {
            let window_clone = window_clone.clone();
            let cancellation = cancellation.clone();

            async move {
                let challenge = TwoFactorChallenge::new(&params);
                let (tx, rx) = mpsc::channel::<String>(1);
                let handler_id = window_clone.listen("2fa-recieved", move |event| {
                    let _ = tx.try_send(event.payload().to_string());
                });
                let _listener = TwoFactorListener {
                    window: window_clone.clone(),
                    event_id: handler_id,
                };
                window_clone
                    .emit("2fa-required", &challenge)
                    .context("Failed to show Apple verification")?;
                Ok(wait_for_two_factor_response(rx, cancellation, &challenge).await?)
            }
            .boxed()
        }
    };

    let mut account = AppleAccount::builder(&email.to_lowercase())
        .err_429_retries(Some(0))
        .anisette_provider(PreservingAnisetteProvider(
            remote_anisette
                // Retain the upstream iloader v2.4.1 compatibility configuration.
                .set_client_info_override(Some(AnisetteClientInfo {
                    client_info:
                        "<Mac15,7> <macOS;27.0;26A5378j> <com.apple.AuthKit/1 (com.apple.akd/1.0)>"
                            .to_string(),
                    user_agent: "akd/1.0 CFNetwork/811.5.4".to_string(),
                })),
        ))
        .login(password, Box::new(tfa_closure))
        .await
        .map_err(safe_auth_error)?;

    let dev_session = DeveloperSession::from_account(&mut account)
        .await
        .map_err(safe_auth_error)?;

    let max_certs_callback: MaxCertsCallbackBox =
        Box::new(move |_certs: Vec<DevelopmentCertificate>| {
            Box::pin(async move { blocked_certificate_selection() })
        });

    // TODO: Team Selection

    let sideloader = SideloaderBuilder::new(dev_session, email.to_lowercase())
        .machine_name("Nanashi Installer".into())
        .storage(create_sideloading_storage(app)?)
        .extensions_behavior(ExtensionsBehaviorSelection::Fixed(
            ExtensionsBehavior::RegisterAll,
        ))
        .max_certs_behavior(MaxCertsBehavior::Prompt(max_certs_callback))
        .build();

    Ok(sideloader)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CertificateInfo {
    pub name: Option<String>,
    pub certificate_id: Option<String>,
    pub serial_number: Option<String>,
    pub machine_name: Option<String>,
    pub machine_id: Option<String>,
}

#[tauri::command]
pub async fn get_certificates(
    sideloader_state: State<'_, SideloaderMutex>,
) -> Result<Vec<CertificateInfo>, AppError> {
    let _operation = crate::nanashi::begin_exclusive_operation()?;
    let mut sideloader = SideloaderGuard::take(&sideloader_state)?;

    let team = sideloader.get_mut().get_team().await?;
    let dev_session = sideloader.get_mut().get_dev_session();

    let certificates = dev_session.list_all_development_certs(&team, None).await?;

    Ok(certificates
        .into_iter()
        .map(|cert| CertificateInfo {
            name: cert.name,
            certificate_id: cert.certificate_id,
            serial_number: cert.serial_number,
            machine_name: cert.machine_name,
            machine_id: cert.machine_id,
        })
        .collect())
}

#[tauri::command]
pub async fn list_app_ids(
    sideloader_state: State<'_, SideloaderMutex>,
) -> Result<ListAppIdsResponse, AppError> {
    let _operation = crate::nanashi::begin_exclusive_operation()?;
    let mut sideloader = SideloaderGuard::take(&sideloader_state)?;

    let team = sideloader.get_mut().get_team().await?;
    let dev_session = sideloader.get_mut().get_dev_session();

    let response = dev_session.list_app_ids(&team, None).await?;

    Ok(response.clone())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn challenge(unknown: bool) -> TwoFactorChallenge {
        let params = TwoFactorCallbackParams {
            last_error: Some("private-provider-error".into()),
            unknown,
            sms: false,
            numbers: vec![isideload::auth::apple_account::TrustedNumber {
                number_with_dial_code: "+33123456789".into(),
                last_two_digits: "89".into(),
                push_mode: "sms".into(),
                id: 7,
            }],
            selected_number_id: None,
        };
        let mut challenge = TwoFactorChallenge::new(&params);
        challenge.request_id = "current-request".into();
        challenge
    }

    #[test]
    fn challenge_masks_phone_numbers_and_discards_raw_errors() {
        let serialized = serde_json::to_string(&challenge(true)).unwrap();
        assert!(serialized.contains("••••89"));
        assert!(serialized.contains("\"hasError\":true"));
        assert!(!serialized.contains("33123456789"));
        assert!(!serialized.contains("private-provider-error"));
    }

    #[test]
    fn method_selection_accepts_only_the_current_challenge_and_trusted_number() {
        let challenge = challenge(true);
        assert!(matches!(
            two_factor_response(
                r#"{"requestId":"current-request","action":"request-sms-code","phoneId":7}"#,
                &challenge,
            )
            .unwrap(),
            TwoFactorCallbackResponse::SendSms(7)
        ));
        assert!(matches!(
            two_factor_response(
                r#"{"requestId":"current-request","action":"request-device-code"}"#,
                &challenge,
            )
            .unwrap(),
            TwoFactorCallbackResponse::SendToDevices
        ));
        for rejected in [
            r#"{"requestId":"old-request","action":"request-device-code"}"#,
            r#"{"requestId":"current-request","action":"request-sms-code","phoneId":999}"#,
            r#"{"requestId":"current-request","action":"submit-code","code":"123456"}"#,
            r#""123456""#,
        ] {
            assert!(two_factor_response(rejected, &challenge).is_err());
        }
    }

    #[test]
    fn typed_code_response_is_bound_to_its_request() {
        let challenge = challenge(false);
        assert!(matches!(two_factor_response(
            r#"{"requestId":"current-request","action":"submit-code","code":"123456"}"#,
            &challenge,
        ).unwrap(), TwoFactorCallbackResponse::SubmitCode(code) if code == "123456"));
        assert!(
            two_factor_response(
                r#"{"requestId":"old-request","action":"submit-code","code":"123456"}"#,
                &challenge,
            )
            .is_err()
        );
    }

    #[test]
    fn anisette_only_accepts_the_reviewed_https_origin() {
        for accepted in [
            ANISETTE_URL,
            "https://mac-ani.jkcoxson.com/",
            "https://mac-ani.jkcoxson.com:443/",
        ] {
            assert_eq!(validated_anisette_url(accepted).unwrap(), ANISETTE_URL);
        }
        for rejected in [
            "http://mac-ani.jkcoxson.com",
            "mac-ani.jkcoxson.com",
            "https://mac-ani.jkcoxson.com.attacker.example",
            "https://mac-ani.jkcoxson.com@attacker.example",
            "https://attacker@mac-ani.jkcoxson.com",
            "https://mac-ani.jkcoxson.com:8443",
            "https://mac-ani.jkcoxson.com/redirect",
            "https://mac-ani.jkcoxson.com?redirect=evil",
            "https://mac-ani.jkcoxson.com#fragment",
            "file:///etc/passwd",
        ] {
            assert!(
                validated_anisette_url(rejected).is_err(),
                "accepted {rejected}"
            );
        }
    }

    #[test]
    fn two_factor_payload_requires_six_ascii_digits() {
        assert_eq!(two_factor_code("\"012345\"").unwrap(), "012345");
        assert_eq!(two_factor_code("\" 123456 \"").unwrap(), "123456");
        for rejected in [
            "123456",
            "null",
            "\"12345\"",
            "\"1234567\"",
            "\"123x56\"",
            "\"１２３４５６\"",
        ] {
            assert!(two_factor_code(rejected).is_err());
        }
    }

    #[test]
    fn certificate_limit_never_selects_certificates_to_revoke() {
        let error = blocked_certificate_selection().unwrap_err();
        assert!(error.iter_reports().any(|cause| cause
            .downcast_current_context::<CertificatesPreserved>()
            .is_some()));
    }

    #[test]
    fn certificate_limit_keeps_its_safe_cause_through_sdk_contexts() {
        let report = blocked_certificate_selection()
            .context("Failed to retrieve certificate identity")
            .context("private-provider-response")
            .unwrap_err();
        assert!(report.iter_reports().any(|cause| cause
            .downcast_current_context::<CertificatesPreserved>()
            .is_some()));
        let error = safe_auth_error(report.into());
        assert!(matches!(error, AppError::Developer(_)));
        assert_eq!(error.to_string(), CERTIFICATES_PRESERVED);
        assert!(!error.to_string().contains("private-provider-response"));
    }

    #[test]
    fn anisette_reprovisioning_requires_explicit_future_recovery_flow() {
        assert!(reject_anisette_reset(false).is_ok());
        let error = reject_anisette_reset(true).unwrap_err();
        assert!(matches!(safe_auth_error(error), AppError::Anisette(_)));
    }

    #[test]
    fn malformed_anisette_state_is_rejected_without_upstream_panic_or_reset() {
        for bytes in [b"broken plist".as_slice(), b"".as_slice()] {
            assert!(validate_stored_anisette_state(bytes).is_err());
        }
        for length in [0, 15, 17] {
            let mut dictionary = plist::Dictionary::new();
            dictionary.insert(
                "keychain_identifier".into(),
                plist::Value::Data(vec![0; length]),
            );
            let mut bytes = Vec::new();
            plist::to_writer_xml(&mut bytes, &dictionary).unwrap();
            assert!(validate_stored_anisette_state(&bytes).is_err());
        }
    }

    #[test]
    fn valid_anisette_identity_is_retained_with_or_without_provisioning_data() {
        let mut dictionary = plist::Dictionary::new();
        dictionary.insert(
            "keychain_identifier".into(),
            plist::Value::Data(vec![0; 16]),
        );
        let mut bytes = Vec::new();
        plist::to_writer_xml(&mut bytes, &dictionary).unwrap();
        assert!(validate_stored_anisette_state(&bytes).is_ok());
        dictionary.insert("adi_pb".into(), plist::Value::Data(vec![1, 2, 3]));
        bytes.clear();
        plist::to_writer_xml(&mut bytes, &dictionary).unwrap();
        assert!(validate_stored_anisette_state(&bytes).is_ok());
        dictionary.insert("adi_pb".into(), plist::Value::String("invalid".into()));
        bytes.clear();
        plist::to_writer_xml(&mut bytes, &dictionary).unwrap();
        assert!(validate_stored_anisette_state(&bytes).is_err());
    }

    #[test]
    fn authentication_errors_keep_the_code_without_server_contents() {
        let report = Err::<(), _>(isideload::SideloadError::AuthWithMessage(
            -80045,
            "private-response-secret".into(),
        ))
        .context("private-request-header")
        .unwrap_err();
        let message = safe_auth_error(report.into()).to_string();
        assert!(message.contains("-80045"));
        assert!(!message.contains("private-response-secret"));
        assert!(!message.contains("private-request-header"));
    }

    #[test]
    fn unknown_authentication_reports_do_not_disclose_response_data() {
        let report = Err::<(), _>(std::io::Error::other("private-network-response"))
            .context("private-context")
            .unwrap_err();
        let message = safe_auth_error(report.into()).to_string();
        assert!(!message.contains("private-network-response"));
        assert!(!message.contains("private-context"));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn waiting_for_two_factor_does_not_block_the_executor() {
        let (sender, receiver) = mpsc::channel(1);
        let submit = async move {
            tokio::task::yield_now().await;
            sender.send("\"012345\"".into()).await.unwrap();
        };
        let challenge = challenge(false);
        let (result, _) = tokio::join!(
            wait_for_two_factor_response(receiver, CancellationToken::new(), &challenge),
            submit
        );
        assert!(
            matches!(result.unwrap(), TwoFactorCallbackResponse::SubmitCode(code) if code == "012345")
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn cancellation_interrupts_pending_two_factor() {
        let (_sender, receiver) = mpsc::channel(1);
        let token = CancellationToken::new();
        token.cancel();
        assert!(matches!(
            wait_for_two_factor_response(receiver, token, &challenge(false)).await,
            Err(AppError::Canceled(_))
        ));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn timeout_drops_pending_auth_without_retrying() {
        let result: Result<(), AppError> = bounded_auth(
            std::future::pending(),
            CancellationToken::new(),
            Duration::from_millis(2),
        )
        .await;
        assert!(matches!(result, Err(AppError::Auth(_))));
    }
}
