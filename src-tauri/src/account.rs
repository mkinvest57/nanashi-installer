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
        teams::TeamsApi,
    },
    sideload::{
        SideloaderBuilder,
        builder::{ExtensionsBehavior, ExtensionsBehaviorSelection, MaxCertsBehavior},
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
    sideload::{AuthenticatedSideloader, SideloaderGuard, SideloaderMutex},
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

impl PreservingAnisetteProvider {
    fn from_storage(
        anisette_url: &str,
        storage: Box<dyn isideload::util::storage::SideloadingStorage>,
    ) -> Result<Self, AppError> {
        // Upstream treats unreadable stored state as absent and has an unchecked
        // 16-byte conversion. Validate first, then load explicitly without replacing it.
        let state_data = storage
            .retrieve_data(isideload::anisette::remote_v3::ANISETTE_STATE_KEY)
            .map_err(|_| {
                AppError::Keyring(
                    "Impossible de lire l’état de connexion dans le trousseau. Il est conservé sans modification.".into()
                )
            })?;
        if let Some(bytes) = state_data.as_ref() {
            validate_stored_anisette_state(bytes)?;
        }
        let mut remote_anisette =
            RemoteV3AnisetteProvider::new(anisette_url, storage, "0".to_string())
                .map_err(|error| classify_auth_error(error, AuthStage::Provider))?;
        if let Some(bytes) = state_data {
            remote_anisette.state = Some(
                plist::from_bytes(&bytes)
                    .map_err(|_| AppError::Anisette(ANISETTE_STATE_PRESERVED.into()))?,
            );
        }
        // Use metadata supplied by the configured provider for this session.
        Ok(Self(remote_anisette))
    }
}

#[async_trait::async_trait]
impl AnisetteProvider for PreservingAnisetteProvider {
    async fn get_anisette_data(&self) -> Result<AnisetteDataResponse, rootcause::Report> {
        provider_request(self.0.get_anisette_data()).await
    }

    async fn resync(&self, sim: &str) -> Result<AnisetteDataResponse, rootcause::Report> {
        provider_request(self.0.resync(sim)).await
    }

    async fn get_client_info(&self) -> Result<AnisetteClientInfo, rootcause::Report> {
        provider_request(self.0.get_client_info()).await
    }

    async fn provision(
        &mut self,
        gs: &Arc<isideload::auth::grandslam::GrandSlam>,
        force_reset: bool,
    ) -> Result<(), rootcause::Report> {
        reject_anisette_reset(force_reset)?;
        provider_request(self.0.provision(gs, false)).await
    }
}

// Preserve the provider stage across SDK contexts, including errors before the
// Apple ID exchange. Do not expose server responses or keychain contents.
async fn provider_request<T>(
    request: impl Future<Output = Result<T, rootcause::Report>>,
) -> Result<T, rootcause::Report> {
    tokio::time::timeout(ANISETTE_TIMEOUT, request)
        .await
        .map_err(|_| rootcause::report!(AuthStage::Provider))?
        .map_err(|report| report.context(AuthStage::Provider).into())
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

#[derive(Clone, Copy, Debug)]
enum AuthDeadline {
    Login,
    TwoFactor,
}

impl AuthDeadline {
    fn message(self) -> &'static str {
        match self {
            Self::Login => "Le délai de connexion Apple est écoulé. Code : AUTH-TIMEOUT.",
            Self::TwoFactor => {
                "Le délai de saisie de la validation Apple est écoulé. Code : AUTH-2FA-TIMEOUT."
            }
        }
    }
}

async fn bounded_auth<T>(
    future: impl Future<Output = Result<T, AppError>>,
    cancellation: CancellationToken,
    timeout: Duration,
    deadline: AuthDeadline,
) -> Result<T, AppError> {
    tokio::select! {
        biased;
        _ = cancellation.cancelled() => Err(AppError::Canceled("Connexion Apple".into())),
        result = tokio::time::timeout(timeout, future) => result.map_err(|_| {
            AppError::Auth(deadline.message().into())
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
        AuthDeadline::TwoFactor,
    )
    .await
}

#[derive(Debug, Clone, Copy, thiserror::Error)]
#[error("Apple sign-in stage")]
enum AuthStage {
    Provider,
    Discovery,
    SignIn,
    TwoFactor,
    DeveloperSession,
}

impl AuthStage {
    fn error(self) -> AppError {
        match self {
            Self::Provider => AppError::Anisette("Le service de préparation de la connexion n’a pas pu terminer sa demande. Code : AUTH-PROVIDER.".into()),
            Self::Discovery => AppError::Auth("Impossible de préparer la connexion aux services Apple. Code : AUTH-DISCOVERY.".into()),
            Self::SignIn => AppError::Auth("L’échange de connexion avec Apple s’est interrompu. Code : AUTH-SIGN-IN.".into()),
            Self::TwoFactor => AppError::Auth("La vérification en deux étapes n’a pas abouti. Code : AUTH-2FA.".into()),
            Self::DeveloperSession => AppError::Auth("La connexion Apple a abouti, mais la session développeur n’a pas pu être préparée. Code : AUTH-DEVELOPER-SESSION.".into()),
        }
    }
}

// Installation preflight calls this after the Apple account has signed in.
pub(crate) fn safe_auth_error(report: rootcause::Report) -> AppError {
    classify_auth_error(report, AuthStage::DeveloperSession)
}

// Do not forward raw authentication responses, attachments, headers or URLs.
fn classify_auth_error(report: rootcause::Report, mut stage: AuthStage) -> AppError {
    if let Some(error) = crate::error::preserved_signature_error(&report) {
        return error;
    }
    let mut transport_failed = false;
    let mut rate_limited = false;
    let mut server_status = None;
    for cause in report.iter_reports() {
        if let Some(origin) = cause.downcast_current_context::<AuthStage>() {
            stage = *origin;
        }
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
        if let Some(error) = cause.downcast_current_context::<AppError>() {
            match error {
                AppError::Canceled(_) => return AppError::Canceled("Vérification Apple".into()),
                AppError::Auth(message) if message == AuthDeadline::TwoFactor.message() => {
                    return AppError::Auth(AuthDeadline::TwoFactor.message().into());
                }
                _ => {}
            }
        }
        if let Some(error) = cause.downcast_current_context::<isideload::SideloadError>() {
            match error {
                isideload::SideloadError::AuthWithMessage(code, _) => {
                    return AppError::Auth(format!("Apple a refusé la demande ({code})."));
                }
                isideload::SideloadError::DeveloperError(code, _) => {
                    return AppError::Developer(format!(
                        "Le service développeur Apple a refusé la demande ({code})."
                    ));
                }
                _ => {}
            }
        }
        let request = cause
            .downcast_current_context::<reqwest::Error>()
            .or_else(
                || match cause.downcast_current_context::<reqwest_middleware::Error>() {
                    Some(reqwest_middleware::Error::Reqwest(error)) => Some(error),
                    _ => None,
                },
            );
        if let Some(request) = request {
            rate_limited |= request.status() == Some(reqwest::StatusCode::TOO_MANY_REQUESTS);
            if let Some(status) = request
                .status()
                .filter(reqwest::StatusCode::is_server_error)
            {
                server_status = Some(status.as_u16());
            }
            transport_failed |= request.is_connect() || request.is_timeout() || request.is_body();
        }
        // In these cases the pinned SDK only emits a fixed context.
        let context = cause
            .downcast_current_context::<&'static str>()
            .copied()
            .or_else(|| {
                cause
                    .downcast_current_context::<String>()
                    .map(String::as_str)
            });
        match context {
            Some("Received 429 Too Many Requests, no retries left") => rate_limited = true,
            Some(
                "Failed to complete trusted device 2FA"
                | "Failed to complete SMS 2FA"
                | "Failed to verify trusted device 2FA",
            ) => stage = AuthStage::TwoFactor,
            _ => {}
        }
    }
    if rate_limited {
        return AppError::Auth("Le service limite temporairement les tentatives. Réessayez plus tard. Code : AUTH-RATE-LIMIT.".into());
    }
    if let Some(status) = server_status {
        return AppError::Auth(format!(
            "Le service de connexion a renvoyé une erreur HTTP {status}. Code : AUTH-SERVICE."
        ));
    }
    if transport_failed
        && !matches!(
            stage,
            AuthStage::Provider | AuthStage::DeveloperSession | AuthStage::TwoFactor
        )
    {
        return AppError::Auth(
            "La communication réseau avec Apple a été interrompue. Code : AUTH-NETWORK.".into(),
        );
    }
    stage.error()
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
    reuse_existing_signature: Option<bool>,
) -> Result<(), AppError> {
    let _operation = crate::nanashi::begin_exclusive_operation()?;
    let account = login(
        &handle,
        window,
        &email,
        &password,
        anisette_server,
        reuse_existing_signature.unwrap_or(false),
    )
    .await?;

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
    let account = login(&handle, window, &email, &password, anisette_server, false).await?;
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
        .map(|account| account.engine.get_email().to_string())
}

#[derive(Serialize)]
pub struct SigningStatus {
    mode: &'static str,
    verified: bool,
}

#[tauri::command]
pub fn signing_status(sideloader_state: State<'_, SideloaderMutex>) -> SigningStatus {
    let session = sideloader_state.lock().unwrap();
    let verified = session
        .as_ref()
        .is_some_and(|account| account.existing_signing.is_some());
    SigningStatus {
        mode: if verified { "existing" } else { "standard" },
        verified,
    }
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
    reuse_existing_signature: bool,
) -> Result<AuthenticatedSideloader, AppError> {
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
            reuse_existing_signature,
        ),
        attempt.0.clone(),
        LOGIN_TIMEOUT,
        AuthDeadline::Login,
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
    reuse_existing_signature: bool,
) -> Result<AuthenticatedSideloader, AppError> {
    let provider = PreservingAnisetteProvider::from_storage(anisette_url, storage)?;
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
                    .context(AuthStage::TwoFactor)?;
                Ok(wait_for_two_factor_response(rx, cancellation, &challenge)
                    .await
                    .context(AuthStage::TwoFactor)?)
            }
            .boxed()
        }
    };

    let mut account = AppleAccount::builder(&email.to_lowercase())
        .err_429_retries(Some(0))
        .anisette_provider(provider)
        .build()
        .await
        .map_err(|error| classify_auth_error(error, AuthStage::Discovery))?;

    let certificate_guard = if reuse_existing_signature {
        Some(crate::existing_signing::install_certificate_guard(
            &mut account,
        )?)
    } else {
        None
    };
    account
        .login(password, Box::new(tfa_closure))
        .await
        .map_err(|error| classify_auth_error(error, AuthStage::SignIn))?;

    let mut dev_session = DeveloperSession::from_account(&mut account)
        .await
        .map_err(safe_auth_error)?;

    let max_certs_callback: MaxCertsCallbackBox =
        Box::new(move |_certs: Vec<DevelopmentCertificate>| {
            Box::pin(async move { blocked_certificate_selection() })
        });

    let existing = if reuse_existing_signature {
        let teams = dev_session.list_teams().await.map_err(|_| {
            AppError::ExistingSignature(
                "Impossible de vérifier l’équipe Apple. Code : EXISTING-NETWORK.".into(),
            )
        })?;
        // Reuse must never silently choose an organization instead of the
        // personal team. Multiple teams need explicit selection in a future UI.
        if teams.len() != 1 {
            return Err(AppError::ExistingSignature(
                "Une équipe Apple unique est nécessaire pour vérifier cette signature. Code : EXISTING-UNVERIFIED.".into()));
        }
        Some(
            crate::existing_signing::resolve_existing_signing(&mut dev_session, email, &teams[0])
                .await?,
        )
    } else {
        None
    };
    if let (Some(guard), Some(existing)) = (&certificate_guard, &existing) {
        guard.pin(&existing.proof)?;
    }
    let (machine_name, signing_storage, proof) = match existing {
        Some(existing) => (
            existing.machine_name,
            existing.storage,
            Some(existing.proof),
        ),
        None => (
            "Nanashi Installer".into(),
            create_sideloading_storage(app)?,
            None,
        ),
    };

    let mut sideloader = SideloaderBuilder::new(dev_session, email.to_lowercase())
        .machine_name(machine_name)
        .storage(signing_storage)
        .extensions_behavior(ExtensionsBehaviorSelection::Fixed(
            ExtensionsBehavior::RegisterAll,
        ))
        .max_certs_behavior(MaxCertsBehavior::Prompt(max_certs_callback))
        .build();

    if let Some(proof) = &proof {
        // Cache and verify the engine's selected team before exposing this
        // session to any installation command.
        let team = sideloader.get_team().await.map_err(|_| {
            AppError::ExistingSignature(
                "Impossible de vérifier l’équipe de signature. Code : EXISTING-NETWORK.".into(),
            )
        })?;
        crate::existing_signing::revalidate_existing_signing(
            sideloader.get_dev_session(),
            &team,
            proof,
        )
        .await?;
    }
    Ok(AuthenticatedSideloader {
        engine: sideloader,
        existing_signing: proof,
    })
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
        assert!(error.iter_reports().any(|cause| {
            cause
                .downcast_current_context::<CertificatesPreserved>()
                .is_some()
        }));
    }

    #[test]
    fn certificate_limit_keeps_its_safe_cause_through_sdk_contexts() {
        let report = blocked_certificate_selection()
            .context("Failed to retrieve certificate identity")
            .context("private-provider-response")
            .unwrap_err();
        assert!(report.iter_reports().any(|cause| {
            cause
                .downcast_current_context::<CertificatesPreserved>()
                .is_some()
        }));
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

    #[test]
    fn unclassified_causes_keep_the_failing_stage_without_server_responses() {
        for (stage, marker) in [
            (AuthStage::Discovery, "AUTH-DISCOVERY"),
            (AuthStage::SignIn, "AUTH-SIGN-IN"),
            (AuthStage::Provider, "AUTH-PROVIDER"),
            (AuthStage::TwoFactor, "AUTH-2FA"),
            (AuthStage::DeveloperSession, "AUTH-DEVELOPER-SESSION"),
        ] {
            let report = rootcause::report!("secret content").attach("secret attachment");
            let error = classify_auth_error(report, stage);
            assert!(error.to_string().contains(marker));
            assert!(!error.to_string().contains("secret"));
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn provider_failure_and_verification_errors_keep_their_origin_through_the_sdk() {
        let provider = provider_request(async { Err::<(), _>(rootcause::report!("secret")) })
            .await
            .context("Failed to get anisette data for login")
            .unwrap_err();
        let error = classify_auth_error(provider.into(), AuthStage::SignIn);
        assert!(matches!(error, AppError::Anisette(_)));
        assert!(error.to_string().contains("AUTH-PROVIDER"));
        let report = rootcause::report!("private response").context("Failed to complete SMS 2FA");
        assert!(
            classify_auth_error(report.into(), AuthStage::SignIn)
                .to_string()
                .contains("AUTH-2FA")
        );
        for (cause, marker, category) in [
            (
                AppError::Canceled("secret".into()),
                "Vérification Apple",
                "canceled",
            ),
            (
                AppError::Auth(AuthDeadline::TwoFactor.message().into()),
                "AUTH-2FA-TIMEOUT",
                "auth",
            ),
        ] {
            let report = rootcause::report!(cause).context(AuthStage::TwoFactor);
            let error = classify_auth_error(report.into(), AuthStage::SignIn);
            assert_eq!(error.as_ref(), category);
            assert!(error.to_string().contains(marker));
            assert!(!error.to_string().contains("secret"));
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn normal_setup_reads_client_information_from_the_provider() {
        // An invalid URL fails locally, before any network request. A hardcoded
        // client-info override would return success and mask this failure.
        let storage = Box::new(isideload::util::storage::InMemoryStorage::new());
        let provider = PreservingAnisetteProvider::from_storage("invalid-url", storage).unwrap();
        let report = provider
            .get_client_info()
            .await
            .expect_err("provider metadata is required");
        let error = classify_auth_error(report, AuthStage::Discovery);
        assert!(error.to_string().contains("AUTH-PROVIDER"));
    }

    #[test]
    fn service_failure_reports_only_the_http_status() {
        let status = http::Response::builder()
            .status(503)
            .body("secret body")
            .unwrap();
        let request_error = reqwest::Response::from(status)
            .error_for_status()
            .unwrap_err()
            .with_url(reqwest::Url::parse("https://example.invalid/private-token").unwrap());
        let report = rootcause::report!(request_error).context("secret diagnostic");
        let error = classify_auth_error(report.into(), AuthStage::SignIn);
        assert!(error.to_string().contains("AUTH-SERVICE"));
        assert!(error.to_string().contains("HTTP 503"));
        assert!(!error.to_string().contains("secret"));
        assert!(!error.to_string().contains("private-token"));
    }

    #[test]
    fn rate_limits_keep_a_safe_diagnostic_with_or_without_sdk_context() {
        let status = http::Response::builder().status(429).body("").unwrap();
        let request_error = reqwest::Response::from(status)
            .error_for_status()
            .unwrap_err();
        for report in [
            rootcause::report!("Received 429 Too Many Requests, no retries left"),
            rootcause::report!(reqwest_middleware::Error::Reqwest(request_error)).into(),
        ] {
            let report = report.context("secret request URL");
            let error = classify_auth_error(report.into(), AuthStage::SignIn);
            assert!(error.to_string().contains("AUTH-RATE-LIMIT"));
            assert!(!error.to_string().contains("secret"));
        }
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
            AuthDeadline::Login,
        )
        .await;
        assert!(result.unwrap_err().to_string().contains("AUTH-TIMEOUT"));
        let verification: Result<(), _> = bounded_auth(
            std::future::pending(),
            CancellationToken::new(),
            Duration::from_millis(2),
            AuthDeadline::TwoFactor,
        )
        .await;
        assert!(
            verification
                .unwrap_err()
                .to_string()
                .contains("AUTH-2FA-TIMEOUT")
        );
    }
}
