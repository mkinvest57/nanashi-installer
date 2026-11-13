//! Reuse an existing local signing identity without creating or revoking certificates.
//!
//! Only the selected account's iloader signing-key entry is read. Authentication
//! and Anisette storage remain in Nanashi's separate keychain namespace.

use std::{
    io::Read,
    path::Path,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime},
};

use http::Extensions;
use isideload::{
    auth::apple_account::AppleAccount,
    dev::{
        certificates::{CertificatesApi, DevelopmentCertificate},
        developer_session::DeveloperSession,
        teams::DeveloperTeam,
    },
    sideload::cert_identity::APPLE_ROOT,
    util::{keyring_storage::KeyringStorage, storage::SideloadingStorage},
};
use reqwest::{Method, Request, Response, Url};
use reqwest_middleware::{ClientBuilder, Middleware, Next};
use rootcause::Report;
use rsa::{
    RsaPrivateKey, pkcs1::EncodeRsaPublicKey, pkcs8::DecodePrivateKey, traits::PublicKeyParts,
};
use sha2::{Digest, Sha256};
use x509_cert::{Certificate, der::Decode};
use zeroize::Zeroizing;

use crate::error::AppError;

const EXISTING_KEY_SERVICE: &str = "iloader";
const DEVELOPER_HOST: &str = "developerservices2.apple.com";

fn failure(code: &str, message: &str) -> AppError {
    AppError::ExistingSignature(format!(
        "{message} Aucun certificat n’a été créé ni révoqué. Code : EXISTING-{code}."
    ))
}

/// A fixed, redacted error. Never include request URLs, bodies, or account data.
#[derive(Debug, thiserror::Error)]
#[error(
    "La réutilisation a bloqué une opération de signature non autorisée. Code : EXISTING-GUARD."
)]
pub(crate) struct CertificateMutationBlocked;

#[derive(Clone, Default)]
pub(crate) struct CertificateGuardHandle(Arc<Mutex<Option<ExistingSigningProof>>>);

impl CertificateGuardHandle {
    pub(crate) fn pin(&self, proof: &ExistingSigningProof) -> Result<(), AppError> {
        let mut selected = self
            .0
            .lock()
            .map_err(|_| failure("GUARD", "La protection de la signature est indisponible."))?;
        if selected.is_some() {
            return Err(failure(
                "GUARD",
                "La signature de cette session a déjà été sélectionnée.",
            ));
        }
        *selected = Some(proof.clone());
        Ok(())
    }
}

#[derive(Clone, Default)]
struct ExistingCertificateGuard(CertificateGuardHandle);

// The pinned SDK has one developer API host. Unknown operations fail closed;
// accepting a new SDK endpoint requires reviewing its effects first.
fn allowed_request(method: &Method, url: &Url) -> bool {
    if url.scheme() != "https"
        || url.port_or_known_default() != Some(443)
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return false;
    }
    match url.host_str() {
        Some(DEVELOPER_HOST) => {
            if method == Method::PATCH {
                // The SDK may enable increased-memory capability for AltStore.
                return url.query().is_none()
                    && url
                        .path()
                        .strip_prefix("/services/v1/bundleIds/")
                        .is_some_and(|id| {
                            !id.is_empty()
                                && id.bytes().all(|v| v.is_ascii_alphanumeric() || v == b'-')
                        });
            }
            if method != Method::POST || url.query() != Some("clientId=XABBG36SBA") {
                return false;
            }
            let Some(operation) = url.path().strip_prefix("/services/QH65B2/") else {
                return false;
            };
            let operation = operation.strip_prefix("ios/").unwrap_or(operation);
            matches!(
                operation,
                "listTeams.action"
                    | "listDevices.action"
                    | "addDevice.action"
                    | "listAllDevelopmentCerts.action"
                    | "listAppIds.action"
                    | "addAppId.action"
                    | "updateAppId.action"
                    | "downloadTeamProvisioningProfile.action"
                    | "listApplicationGroups.action"
                    | "addApplicationGroup.action"
                    | "assignApplicationGroupToAppId.action"
            )
        }
        // These hosts serve the SDK's authentication URL bag and 2FA flow.
        // Developer-service requests cannot be redirected through them because
        // redirects are disabled on this session's underlying HTTP client.
        Some("gsa.apple.com" | "idmsa.apple.com") => {
            (url.path().starts_with("/grandslam/")
                || url.path() == "/auth"
                || url.path().starts_with("/auth/")
                || url.path().starts_with("/appleauth/"))
                && !url.path().to_ascii_lowercase().contains("certificate")
                && !url.path().to_ascii_lowercase().contains("developmentcert")
                && !url.path().to_ascii_lowercase().contains("developmentcsr")
        }
        _ => false,
    }
}

#[async_trait::async_trait]
impl Middleware for ExistingCertificateGuard {
    async fn handle(
        &self,
        request: Request,
        extensions: &mut Extensions,
        next: Next<'_>,
    ) -> reqwest_middleware::Result<Response> {
        if !allowed_request(request.method(), request.url()) {
            return Err(reqwest_middleware::Error::middleware(
                CertificateMutationBlocked,
            ));
        }
        let proof = self
            .0
            .0
            .lock()
            .map_err(|_| reqwest_middleware::Error::middleware(CertificateMutationBlocked))?
            .clone();
        let developer_request = request.url().host_str() == Some(DEVELOPER_HOST);
        let certificate_list = developer_request
            && request
                .url()
                .path()
                .ends_with("/listAllDevelopmentCerts.action");
        if developer_request {
            if let Some(proof) = &proof {
                if !request_matches_team(&request, &proof.team_id) {
                    return Err(reqwest_middleware::Error::middleware(
                        CertificateMutationBlocked,
                    ));
                }
            } else if !certificate_list && !request.url().path().ends_with("/listTeams.action") {
                // Until selection is verified, allow only the reads needed to
                // select the original identity. No account mutation is allowed.
                return Err(reqwest_middleware::Error::middleware(
                    CertificateMutationBlocked,
                ));
            }
        }
        let response = next.run(request, extensions).await?;
        if certificate_list && let Some(proof) = proof {
            checked_certificate_response(response, &proof).await
        } else {
            Ok(response)
        }
    }
}

fn request_matches_team(request: &Request, team_id: &str) -> bool {
    if request.url().path().ends_with("/listTeams.action") {
        return true;
    }
    let Some(bytes) = request.body().and_then(|body| body.as_bytes()) else {
        return false;
    };
    if request.method() == Method::PATCH {
        serde_json::from_slice::<serde_json::Value>(bytes)
            .ok()
            .and_then(|value| {
                value
                    .pointer("/data/attributes/teamId")
                    .and_then(|v| v.as_str())
                    .map(str::to_owned)
            })
            .as_deref()
            == Some(team_id)
    } else {
        plist::from_bytes::<plist::Dictionary>(bytes)
            .ok()
            .and_then(|value| {
                value
                    .get("teamId")
                    .and_then(|v| v.as_string())
                    .map(str::to_owned)
            })
            .as_deref()
            == Some(team_id)
    }
}

async fn checked_certificate_response(
    mut response: Response,
    proof: &ExistingSigningProof,
) -> reqwest_middleware::Result<Response> {
    let invalid = || {
        reqwest_middleware::Error::middleware(failure(
            "UNVERIFIED",
            "La réponse de vérification du certificat Apple est invalide.",
        ))
    };
    if !response.status().is_success() {
        return Err(invalid());
    }
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|_| invalid())? {
        if body.len() + chunk.len() > 4 * 1024 * 1024 {
            return Err(invalid());
        }
        body.extend_from_slice(&chunk);
    }
    validate_certificate_response(&body, proof, SystemTime::now())
        .map_err(reqwest_middleware::Error::middleware)?;
    let mut rebuilt = http::Response::builder()
        .status(response.status())
        .version(response.version());
    *rebuilt.headers_mut().ok_or_else(invalid)? = response.headers().clone();
    Ok(rebuilt.body(body).map_err(|_| invalid())?.into())
}

fn validate_certificate_response(
    body: &[u8],
    proof: &ExistingSigningProof,
    now: SystemTime,
) -> Result<(), AppError> {
    let invalid = || {
        failure(
            "UNVERIFIED",
            "Apple n’a pas confirmé la signature sélectionnée pour cette session.",
        )
    };
    let value: plist::Dictionary = plist::from_bytes(body).map_err(|_| invalid())?;
    if value.get("resultCode").and_then(|v| v.as_signed_integer()) != Some(0) {
        return Err(invalid());
    }
    let certificates: Vec<DevelopmentCertificate> =
        plist::from_value(value.get("certificates").ok_or_else(invalid)?).map_err(|_| invalid())?;
    let current = choose_certificate(&certificates, &proof.public_key, &proof.team_id, now)?;
    ensure_same_proof(&current, proof)
}

/// Must run before login, before the GrandSlam Arc is shared with a session.
pub(crate) fn install_certificate_guard(
    account: &mut AppleAccount,
) -> Result<CertificateGuardHandle, AppError> {
    let grandslam = Arc::get_mut(&mut account.grandslam_client)
        .ok_or_else(|| failure("GUARD", "La session de signature ne peut pas être isolée."))?;
    let root = reqwest::Certificate::from_der(APPLE_ROOT).map_err(|_| {
        failure(
            "GUARD",
            "La protection de la signature n’a pas pu être initialisée.",
        )
    })?;
    // Preserve the SDK's TLS trust configuration and header behavior. Build a
    // fresh client because its default redirect policy would bypass middleware
    // validation on a redirected request. No authenticated session exists yet.
    let client = reqwest::Client::builder()
        .add_root_certificate(root)
        .http1_title_case_headers()
        .https_only(true)
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(15))
        .timeout(Duration::from_secs(45))
        .build()
        .map_err(|_| {
            failure(
                "GUARD",
                "La protection de la signature n’a pas pu être initialisée.",
            )
        })?;
    let handle = CertificateGuardHandle::default();
    grandslam.client = ClientBuilder::new(client)
        .with(ExistingCertificateGuard(handle.clone()))
        .build();
    Ok(handle)
}

fn signing_key_entry(email: &str) -> String {
    format!("{:x}/key", Sha256::digest(email.to_lowercase().as_bytes()))
}

struct ReadOnlySigningKey {
    entry: String,
    bytes: Zeroizing<Vec<u8>>,
}

impl SideloadingStorage for ReadOnlySigningKey {
    fn store(&self, _key: &str, _value: &str) -> Result<(), Report> {
        Err(CertificateMutationBlocked.into())
    }

    fn retrieve(&self, _key: &str) -> Result<Option<String>, Report> {
        // The certificate path uses retrieve_data; textual/authentication reads
        // from this single-purpose adapter must never escape to another vault.
        Err(CertificateMutationBlocked.into())
    }

    fn store_data(&self, _key: &str, _value: &[u8]) -> Result<(), Report> {
        Err(CertificateMutationBlocked.into())
    }

    fn retrieve_data(&self, key: &str) -> Result<Option<Vec<u8>>, Report> {
        if key != self.entry {
            return Err(CertificateMutationBlocked.into());
        }
        Ok(Some(self.bytes.to_vec()))
    }

    fn delete(&self, _key: &str) -> Result<(), Report> {
        Err(CertificateMutationBlocked.into())
    }
}

/// Public verification material only; no private key or Apple credentials.
#[derive(Clone)]
pub(crate) struct ExistingSigningProof {
    team_id: String,
    machine_name: String,
    machine_id: String,
    certificate_sha256: [u8; 32],
    public_key: Vec<u8>,
}

pub(crate) struct ExistingSigning {
    pub machine_name: String,
    pub storage: Box<dyn SideloadingStorage>,
    pub proof: ExistingSigningProof,
}

fn public_key_from_private(bytes: &[u8]) -> Result<Vec<u8>, AppError> {
    let key = RsaPrivateKey::from_pkcs8_der(bytes).map_err(|_| {
        failure(
            "KEY-INVALID",
            "La clé de signature iloader est illisible. Elle a été conservée.",
        )
    })?;
    key.validate().map_err(|_| {
        failure(
            "KEY-INVALID",
            "La clé de signature iloader est invalide. Elle a été conservée.",
        )
    })?;
    if key.n().bits() < 2048 {
        return Err(failure(
            "KEY-INVALID",
            "La clé de signature existante n’est pas compatible.",
        ));
    }
    key.to_public_key()
        .to_pkcs1_der()
        .map(|der| der.as_bytes().to_vec())
        .map_err(|_| {
            failure(
                "KEY-INVALID",
                "La clé de signature existante n’est pas compatible.",
            )
        })
}

fn certificate_team_matches(certificate: &Certificate, team_id: &str) -> bool {
    let mut units = certificate
        .tbs_certificate
        .subject
        .0
        .iter()
        .flat_map(|rdn| rdn.0.iter())
        .filter(|attribute| attribute.oid.to_string() == "2.5.4.11");
    // Apple development certificates carry the team identifier in the OU.
    // Require exactly one OU to avoid accepting ambiguous subject names.
    units
        .next()
        .is_some_and(|unit| unit.value.value() == team_id.as_bytes())
        && units.next().is_none()
}

fn active_certificate(metadata: &DevelopmentCertificate) -> bool {
    if metadata.status_code.is_some_and(|code| code != 0) {
        return false;
    }
    match metadata.status.as_deref() {
        Some(status) => matches!(
            status.to_ascii_lowercase().as_str(),
            "issued" | "active" | "valid"
        ),
        None => metadata.status_code == Some(0),
    }
}

fn choose_certificate(
    certificates: &[DevelopmentCertificate],
    public_key: &[u8],
    team_id: &str,
    now: SystemTime,
) -> Result<ExistingSigningProof, AppError> {
    if team_id.len() != 10
        || !team_id
            .bytes()
            .all(|v| v.is_ascii_uppercase() || v.is_ascii_digit())
    {
        return Err(failure(
            "UNVERIFIED",
            "L’équipe de signature Apple n’a pas pu être vérifiée.",
        ));
    }
    let mut matching = Vec::new();
    for metadata in certificates {
        let Some(bytes) = metadata.cert_content.as_ref() else {
            continue;
        };
        let certificate = Certificate::from_der(bytes.as_ref())
            .map_err(|_| failure("UNVERIFIED", "Apple a renvoyé un certificat illisible."))?;
        if certificate
            .tbs_certificate
            .subject_public_key_info
            .subject_public_key
            .as_bytes()
            == Some(public_key)
        {
            matching.push((metadata, certificate, bytes));
        }
    }
    // The SDK selects the first matching key/name. Do not let list ordering
    // choose between duplicate certificates, even when one is expired.
    if matching.len() > 1 {
        return Err(failure(
            "CERTIFICATE-AMBIGUOUS",
            "Plusieurs certificats correspondent à cette clé. La signature doit être vérifiée avant de continuer.",
        ));
    }
    let Some((metadata, certificate, bytes)) = matching.pop() else {
        return Err(failure(
            "CERTIFICATE-MISMATCH",
            "La clé iloader de ce Mac ne correspond à aucun certificat de ce compte Apple.",
        ));
    };
    if !certificate_team_matches(&certificate, team_id) {
        return Err(failure(
            "CERTIFICATE-MISMATCH",
            "Le certificat existant ne correspond pas à l’équipe Apple sélectionnée.",
        ));
    }
    let validity = certificate.tbs_certificate.validity;
    if now < validity.not_before.to_system_time()
        || now >= validity.not_after.to_system_time()
        || metadata
            .expiration_date
            .is_some_and(|date| now >= SystemTime::from(date))
    {
        return Err(failure(
            "CERTIFICATE-EXPIRED",
            "Le certificat existant n’est pas valide à cette date. Il a été conservé.",
        ));
    }
    if !active_certificate(metadata) {
        return Err(failure(
            "UNVERIFIED",
            "Apple n’a pas confirmé que le certificat existant est actif.",
        ));
    }
    let (Some(machine_name), Some(machine_id), Some(certificate_id)) = (
        &metadata.machine_name,
        &metadata.machine_id,
        &metadata.certificate_id,
    ) else {
        return Err(failure(
            "UNVERIFIED",
            "Les informations du certificat existant sont incomplètes.",
        ));
    };
    if machine_name.is_empty() || machine_id.is_empty() || certificate_id.is_empty() {
        return Err(failure(
            "UNVERIFIED",
            "Les informations du certificat existant sont incomplètes.",
        ));
    }
    Ok(ExistingSigningProof {
        team_id: team_id.to_string(),
        machine_name: machine_name.clone(),
        machine_id: machine_id.clone(),
        certificate_sha256: Sha256::digest(bytes.as_ref()).into(),
        public_key: public_key.to_vec(),
    })
}

pub(crate) async fn resolve_existing_signing(
    developer: &mut DeveloperSession,
    email: &str,
    team: &DeveloperTeam,
) -> Result<ExistingSigning, AppError> {
    let entry = signing_key_entry(email);
    let storage = KeyringStorage::new(EXISTING_KEY_SERVICE.to_string());
    let bytes = Zeroizing::new(storage.retrieve_data(&entry)
        .map_err(|_| failure("KEY-INVALID", "Le trousseau n’a pas permis de lire la clé iloader. Déverrouillez-le puis réessayez."))?
        .ok_or_else(|| failure("KEY-MISSING", "La clé de signature iloader de ce compte n’a pas été trouvée sur ce Mac. Conservez vos apps actuelles."))?);
    let public_key = public_key_from_private(&bytes)?;
    let certificates = developer.list_ios_certs(team).await
        .map_err(|report| crate::error::preserved_signature_error(&report).unwrap_or_else(||
            failure("NETWORK", "La vérification du certificat auprès d’Apple a échoué. Réessayez lorsque la connexion sera disponible.")))?;
    let proof = choose_certificate(&certificates, &public_key, &team.team_id, SystemTime::now())?;
    Ok(ExistingSigning {
        machine_name: proof.machine_name.clone(),
        storage: Box::new(ReadOnlySigningKey { entry, bytes }),
        proof,
    })
}

pub(crate) async fn revalidate_existing_signing(
    developer: &mut DeveloperSession,
    team: &DeveloperTeam,
    proof: &ExistingSigningProof,
) -> Result<(), AppError> {
    if team.team_id != proof.team_id {
        return Err(failure(
            "CERTIFICATE-MISMATCH",
            "L’équipe de signature a changé. Reconnectez le compte d’origine.",
        ));
    }
    let certificates = developer.list_ios_certs(team).await.map_err(|report| {
        crate::error::preserved_signature_error(&report).unwrap_or_else(|| failure(
            "NETWORK",
            "Apple n’a pas confirmé l’état actuel du certificat. L’installation n’a pas commencé.",
        ))
    })?;
    let current = choose_certificate(
        &certificates,
        &proof.public_key,
        &proof.team_id,
        SystemTime::now(),
    )?;
    ensure_same_proof(&current, proof)
}

fn ensure_same_proof(
    current: &ExistingSigningProof,
    proof: &ExistingSigningProof,
) -> Result<(), AppError> {
    if current.team_id != proof.team_id
        || current.certificate_sha256 != proof.certificate_sha256
        || current.machine_name != proof.machine_name
        || current.machine_id != proof.machine_id
    {
        return Err(failure(
            "CERTIFICATE-MISMATCH",
            "La signature Apple a changé depuis la connexion. Reconnectez-vous pour la vérifier.",
        ));
    }
    Ok(())
}

fn read_embedded_file(path: &Path) -> Result<Vec<u8>, AppError> {
    const MAX_EMBEDDED_FILE: u64 = 1024 * 1024;
    let invalid = || {
        failure(
            "UNVERIFIED",
            "Les éléments de signature préparés pour AltStore sont illisibles.",
        )
    };
    let metadata = std::fs::symlink_metadata(path).map_err(|_| invalid())?;
    if !metadata.file_type().is_file() || metadata.len() > MAX_EMBEDDED_FILE {
        return Err(invalid());
    }
    let file = std::fs::File::open(path).map_err(|_| invalid())?;
    let mut bytes = Vec::new();
    file.take(MAX_EMBEDDED_FILE + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| invalid())?;
    if bytes.len() as u64 > MAX_EMBEDDED_FILE {
        return Err(invalid());
    }
    Ok(bytes)
}

/// Check the identity AltStore will import before uploading the signed bundle.
/// The engine's signature alone is insufficient: an unusable embedded identity
/// could make AltStore fall back to requesting a different certificate later.
pub(crate) fn verify_embedded_identity(
    bundle: &Path,
    proof: &ExistingSigningProof,
) -> Result<(), AppError> {
    let invalid = || {
        failure(
            "UNVERIFIED",
            "L’identité de signature préparée pour AltStore n’a pas pu être vérifiée.",
        )
    };
    let mismatch = || {
        failure(
            "CERTIFICATE-MISMATCH",
            "L’identité intégrée à AltStore ne correspond pas à la signature existante sélectionnée.",
        )
    };
    let directory = std::fs::symlink_metadata(bundle).map_err(|_| invalid())?;
    if !directory.file_type().is_dir() {
        return Err(invalid());
    }
    let info_bytes = read_embedded_file(&bundle.join("Info.plist"))?;
    let info: plist::Dictionary = plist::from_bytes(&info_bytes).map_err(|_| invalid())?;
    let serial = info
        .get("ALTCertificateID")
        .and_then(|v| v.as_string())
        .ok_or_else(invalid)?;
    if serial.is_empty()
        || !serial
            .bytes()
            .all(|v| v.is_ascii_digit() || (b'A'..=b'F').contains(&v))
    {
        return Err(invalid());
    }
    let archive_bytes = Zeroizing::new(read_embedded_file(&bundle.join("ALTCertificate.p12"))?);
    let archive = openssl::pkcs12::Pkcs12::from_der(&archive_bytes)
        .map_err(|_| invalid())?
        .parse2(&proof.machine_id)
        .map_err(|_| invalid())?;
    let certificate = archive.cert.ok_or_else(invalid)?;
    let private_key = archive.pkey.ok_or_else(invalid)?;
    let certificate_der = certificate.to_der().map_err(|_| invalid())?;
    let digest: [u8; 32] = Sha256::digest(&certificate_der).into();
    if digest != proof.certificate_sha256 {
        return Err(mismatch());
    }
    let public_key = certificate.public_key().map_err(|_| invalid())?;
    if !private_key.public_eq(&public_key) {
        return Err(mismatch());
    }
    let parsed = Certificate::from_der(&certificate_der).map_err(|_| invalid())?;
    if !certificate_team_matches(&parsed, &proof.team_id)
        || parsed
            .tbs_certificate
            .subject_public_key_info
            .subject_public_key
            .as_bytes()
            != Some(proof.public_key.as_slice())
    {
        return Err(mismatch());
    }
    let expected_serial = parsed
        .tbs_certificate
        .serial_number
        .as_bytes()
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect::<String>();
    if serial != expected_serial.trim_start_matches('0') {
        return Err(mismatch());
    }
    let now = SystemTime::now();
    if now < parsed.tbs_certificate.validity.not_before.to_system_time()
        || now >= parsed.tbs_certificate.validity.not_after.to_system_time()
    {
        return Err(failure(
            "CERTIFICATE-EXPIRED",
            "Le certificat intégré à AltStore n’est plus valide à cette date.",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsa::pkcs8::EncodePrivateKey;
    use std::{
        sync::{
            LazyLock,
            atomic::{AtomicUsize, Ordering},
        },
        time::UNIX_EPOCH,
    };
    use x509_cert::der::{Encode, asn1::BitString};

    const TEAM: &str = "ABCDEFGHIJ";
    static PRIVATE: LazyLock<RsaPrivateKey> =
        LazyLock::new(|| RsaPrivateKey::new(&mut rand::thread_rng(), 2048).unwrap());

    fn public_key() -> Vec<u8> {
        PRIVATE
            .to_public_key()
            .to_pkcs1_der()
            .unwrap()
            .as_bytes()
            .to_vec()
    }
    fn now() -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(1_800_000_000)
    }

    fn fixture(team: &str, key: &[u8]) -> DevelopmentCertificate {
        // The selector receives authenticated Apple API material in production.
        // This DER fixture exercises its fields, not chain-signature validation.
        let mut certificate = Certificate::from_der(APPLE_ROOT).unwrap();
        certificate.tbs_certificate.subject = format!("CN=Unit Test,OU={team}").parse().unwrap();
        certificate
            .tbs_certificate
            .subject_public_key_info
            .subject_public_key = BitString::from_bytes(key).unwrap();
        certificate.tbs_certificate.validity.not_before =
            (now() - Duration::from_secs(3600)).try_into().unwrap();
        certificate.tbs_certificate.validity.not_after =
            (now() + Duration::from_secs(3600)).try_into().unwrap();
        DevelopmentCertificate {
            name: Some("Unit test".into()),
            certificate_id: Some("CERTID1234".into()),
            serial_number: Some("01".into()),
            machine_id: Some("test-machine-id".into()),
            machine_name: Some("iloader".into()),
            cert_content: Some(certificate.to_der().unwrap().into()),
            certificate_platform: Some("ios".into()),
            certificate_type: None,
            status: Some("Issued".into()),
            status_code: Some(0),
            expiration_date: None,
        }
    }

    fn has_code<T>(result: Result<T, AppError>, code: &str) {
        match result {
            Err(error) => assert!(error.to_string().contains(code), "{error}"),
            Ok(_) => panic!("Expected rejection {code}"),
        }
    }

    #[test]
    fn key_entry_uses_one_hash_of_normalized_account() {
        assert_eq!(
            signing_key_entry("User@Example.com"),
            "b4c9a289323b21a01c3e940f150eb9b8c542587f1abfd8f0e1cc1ffc5e475514/key"
        );
    }

    #[test]
    fn accepts_only_matching_active_identity() {
        let key = public_key();
        let certificate = fixture(TEAM, &key);
        let proof = choose_certificate(&[certificate], &key, TEAM, now()).unwrap();
        assert_eq!(proof.machine_name, "iloader");
        assert_eq!(proof.team_id, TEAM);
    }

    #[test]
    fn rejects_wrong_key_team_and_duplicate_certificates() {
        let key = public_key();
        let certificate = fixture(TEAM, &key);
        has_code(
            choose_certificate(&[certificate.clone()], b"another key", TEAM, now()),
            "CERTIFICATE-MISMATCH",
        );
        has_code(
            choose_certificate(&[certificate.clone()], &key, "1234567890", now()),
            "CERTIFICATE-MISMATCH",
        );
        has_code(
            choose_certificate(&[certificate.clone(), certificate], &key, TEAM, now()),
            "CERTIFICATE-AMBIGUOUS",
        );
    }

    #[test]
    fn rejects_expired_not_yet_valid_and_revoked_certificates() {
        let key = public_key();
        let mut certificate = fixture(TEAM, &key);
        has_code(
            choose_certificate(
                &[certificate.clone()],
                &key,
                TEAM,
                now() + Duration::from_secs(3600),
            ),
            "CERTIFICATE-EXPIRED",
        );
        has_code(
            choose_certificate(
                &[certificate.clone()],
                &key,
                TEAM,
                now() - Duration::from_secs(3601),
            ),
            "CERTIFICATE-EXPIRED",
        );
        certificate.status = Some("Revoked".into());
        has_code(
            choose_certificate(&[certificate], &key, TEAM, now()),
            "UNVERIFIED",
        );
    }

    #[test]
    fn rejects_missing_status_and_metadata() {
        let key = public_key();
        let mut certificate = fixture(TEAM, &key);
        certificate.status = None;
        certificate.status_code = None;
        has_code(
            choose_certificate(&[certificate.clone()], &key, TEAM, now()),
            "UNVERIFIED",
        );
        certificate.status = Some("Issued".into());
        certificate.machine_id = None;
        has_code(
            choose_certificate(&[certificate], &key, TEAM, now()),
            "UNVERIFIED",
        );
    }

    #[test]
    fn validates_private_key_and_forbids_all_storage_mutation() {
        let der = PRIVATE.to_pkcs8_der().unwrap();
        assert_eq!(
            public_key_from_private(der.as_bytes()).unwrap(),
            public_key()
        );
        has_code(public_key_from_private(b"not a signing key"), "KEY-INVALID");
        let storage = ReadOnlySigningKey {
            entry: signing_key_entry("user@example.com"),
            bytes: Zeroizing::new(der.as_bytes().to_vec()),
        };
        assert_eq!(
            storage.retrieve_data(&storage.entry).unwrap().unwrap(),
            der.as_bytes()
        );
        assert!(storage.retrieve_data("another-account/key").is_err());
        assert!(storage.retrieve("password").is_err());
        assert!(storage.store(&storage.entry, "replacement").is_err());
        assert!(storage.store_data(&storage.entry, b"replacement").is_err());
        assert!(storage.delete(&storage.entry).is_err());
        assert_eq!(
            storage.retrieve_data(&storage.entry).unwrap().unwrap(),
            der.as_bytes()
        );
    }

    #[derive(Clone)]
    struct CountTransport(Arc<AtomicUsize>);
    #[async_trait::async_trait]
    impl Middleware for CountTransport {
        async fn handle(
            &self,
            _: Request,
            _: &mut Extensions,
            _: Next<'_>,
        ) -> reqwest_middleware::Result<Response> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Ok(http::Response::builder()
                .status(200)
                .body("{}".to_string())
                .unwrap()
                .into())
        }
    }

    #[tokio::test]
    async fn forbidden_developer_requests_never_reach_transport() {
        let calls = Arc::new(AtomicUsize::new(0));
        let client = ClientBuilder::new(reqwest::Client::new())
            .with(ExistingCertificateGuard::default())
            .with(CountTransport(calls.clone()))
            .build();
        for path in [
            "ios/submitDevelopmentCSR.action",
            "submitDevelopmentCSR.action",
            "ios/revokeDevelopmentCert.action",
            "revokeDevelopmentCert.action",
            "ios/deleteAppId.action",
            "ios/createCertificate.action",
            "ios/unknownFutureMutation.action",
        ] {
            let error = client
                .post(format!(
                    "https://{DEVELOPER_HOST}/services/QH65B2/{path}?clientId=XABBG36SBA"
                ))
                .send()
                .await
                .unwrap_err();
            assert!(error.to_string().contains("EXISTING-GUARD"));
        }
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        client.post(format!("https://{DEVELOPER_HOST}/services/QH65B2/ios/listAllDevelopmentCerts.action?clientId=XABBG36SBA")).send().await.unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn guard_rejects_aliases_other_hosts_and_methods() {
        for url in [
            "https://developerservices2.apple.com/services/v1/certificates",
            "https://developerservices2.apple.com/services/QH65B2/ios/listAppIds.action?clientId=XABBG36SBA&action=revokeDevelopmentCert",
            "http://developerservices2.apple.com/services/QH65B2/ios/listAppIds.action?clientId=XABBG36SBA",
            "https://developerservices2.apple.com.evil.test/services/QH65B2/ios/listAppIds.action?clientId=XABBG36SBA",
            "https://gsa.apple.com/services/QH65B2/ios/revokeDevelopmentCert.action",
            "https://developerservices2.apple.com/services/QH65B2/ios/%73ubmitDevelopmentCSR.action?clientId=XABBG36SBA",
        ] {
            assert!(
                !allowed_request(&Method::POST, &Url::parse(url).unwrap()),
                "{url}"
            );
        }
        let allowed = Url::parse("https://developerservices2.apple.com/services/QH65B2/ios/listAppIds.action?clientId=XABBG36SBA").unwrap();
        assert!(!allowed_request(&Method::DELETE, &allowed));
        assert!(allowed_request(&Method::POST, &allowed));
        assert!(allowed_request(
            &Method::POST,
            &Url::parse("https://gsa.apple.com/grandslam/GsService2").unwrap()
        ));
    }

    fn certificate_reply(certificates: Vec<DevelopmentCertificate>) -> Vec<u8> {
        #[derive(serde::Serialize)]
        struct Reply {
            #[serde(rename = "resultCode")]
            result_code: i64,
            certificates: Vec<DevelopmentCertificate>,
        }
        let mut bytes = Vec::new();
        plist::to_writer_xml(
            &mut bytes,
            &Reply {
                result_code: 0,
                certificates,
            },
        )
        .unwrap();
        bytes
    }

    fn team_body(team: &str) -> Vec<u8> {
        let mut dictionary = plist::Dictionary::new();
        dictionary.insert("teamId".into(), team.into());
        let mut bytes = Vec::new();
        plist::to_writer_xml(&mut bytes, &dictionary).unwrap();
        bytes
    }

    #[test]
    fn pinned_certificate_rejects_later_changes_and_ambiguity() {
        let key = public_key();
        let original = fixture(TEAM, &key);
        let proof = choose_certificate(&[original.clone()], &key, TEAM, now()).unwrap();
        validate_certificate_response(&certificate_reply(vec![original.clone()]), &proof, now())
            .unwrap();
        let mut changed = original.clone();
        changed.machine_id = Some("different-signing-machine".into());
        has_code(
            validate_certificate_response(&certificate_reply(vec![changed]), &proof, now()),
            "CERTIFICATE-MISMATCH",
        );
        has_code(
            validate_certificate_response(
                &certificate_reply(vec![original.clone(), original]),
                &proof,
                now(),
            ),
            "CERTIFICATE-AMBIGUOUS",
        );
        has_code(
            validate_certificate_response(b"not an Apple plist", &proof, now()),
            "UNVERIFIED",
        );
        has_code(
            validate_certificate_response(&certificate_reply(vec![]), &proof, now()),
            "CERTIFICATE-MISMATCH",
        );
    }

    #[derive(Clone)]
    struct CertificateResponse(Vec<u8>, Arc<AtomicUsize>);
    #[async_trait::async_trait]
    impl Middleware for CertificateResponse {
        async fn handle(
            &self,
            _: Request,
            _: &mut Extensions,
            _: Next<'_>,
        ) -> reqwest_middleware::Result<Response> {
            self.1.fetch_add(1, Ordering::SeqCst);
            Ok(http::Response::builder()
                .status(200)
                .header("Content-Type", "text/x-xml-plist")
                .body(self.0.clone())
                .unwrap()
                .into())
        }
    }

    #[tokio::test]
    async fn pinned_middleware_checks_subsequent_sdk_reads_and_team() {
        let key = public_key();
        let mut metadata = fixture(TEAM, &key);
        let mut certificate =
            Certificate::from_der(metadata.cert_content.as_ref().unwrap().as_ref()).unwrap();
        let current = SystemTime::now();
        certificate.tbs_certificate.validity.not_before =
            (current - Duration::from_secs(3600)).try_into().unwrap();
        certificate.tbs_certificate.validity.not_after =
            (current + Duration::from_secs(3600)).try_into().unwrap();
        metadata.cert_content = Some(certificate.to_der().unwrap().into());
        let proof = choose_certificate(&[metadata.clone()], &key, TEAM, current).unwrap();
        let handle = CertificateGuardHandle::default();
        handle.pin(&proof).unwrap();
        assert!(handle.pin(&proof).is_err());
        let calls = Arc::new(AtomicUsize::new(0));
        let body = certificate_reply(vec![metadata.clone()]);
        let client = ClientBuilder::new(reqwest::Client::new())
            .with(ExistingCertificateGuard(handle.clone()))
            .with(CertificateResponse(body.clone(), calls.clone()))
            .build();
        let url = format!(
            "https://{DEVELOPER_HOST}/services/QH65B2/ios/listAllDevelopmentCerts.action?clientId=XABBG36SBA"
        );
        assert!(
            client
                .post(&url)
                .body(team_body("0000000000"))
                .send()
                .await
                .is_err()
        );
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        let response = client
            .post(&url)
            .body(team_body(TEAM))
            .send()
            .await
            .unwrap();
        assert_eq!(
            response.headers().get("Content-Type").unwrap(),
            "text/x-xml-plist"
        );
        assert_eq!(response.bytes().await.unwrap().as_ref(), body);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        metadata.machine_id = Some("changed-after-preflight".into());
        let client = ClientBuilder::new(reqwest::Client::new())
            .with(ExistingCertificateGuard(handle))
            .with(CertificateResponse(
                certificate_reply(vec![metadata]),
                calls.clone(),
            ))
            .build();
        let error = client
            .post(&url)
            .body(team_body(TEAM))
            .send()
            .await
            .unwrap_err();
        assert!(error.to_string().contains("CERTIFICATE-MISMATCH"));
    }

    fn embedded_identity_fixture(
        serial: u32,
    ) -> (
        isideload::sideload::cert_identity::CertificateIdentity,
        ExistingSigningProof,
    ) {
        use openssl::{
            asn1::Asn1Time,
            bn::BigNum,
            hash::MessageDigest,
            pkey::PKey,
            x509::{X509, X509NameBuilder},
        };
        let private_der = PRIVATE.to_pkcs8_der().unwrap();
        let key = PKey::private_key_from_der(private_der.as_bytes()).unwrap();
        let mut name = X509NameBuilder::new().unwrap();
        name.append_entry_by_text("CN", "Nanashi generated unit test")
            .unwrap();
        name.append_entry_by_text("OU", TEAM).unwrap();
        let name = name.build();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let mut builder = X509::builder().unwrap();
        builder.set_version(2).unwrap();
        builder.set_subject_name(&name).unwrap();
        builder.set_issuer_name(&name).unwrap();
        builder.set_pubkey(&key).unwrap();
        builder
            .set_serial_number(&BigNum::from_u32(serial).unwrap().to_asn1_integer().unwrap())
            .unwrap();
        builder
            .set_not_before(&Asn1Time::from_unix(now - 3600).unwrap())
            .unwrap();
        builder
            .set_not_after(&Asn1Time::from_unix(now + 3600).unwrap())
            .unwrap();
        builder.sign(&key, MessageDigest::sha256()).unwrap();
        let certificate_der = builder.build().to_der().unwrap();
        let certificate = Certificate::from_der(&certificate_der).unwrap();
        let mut metadata = fixture(TEAM, &public_key());
        metadata.cert_content = Some(certificate_der.into());
        let proof =
            choose_certificate(&[metadata], &public_key(), TEAM, SystemTime::now()).unwrap();
        let identity = isideload::sideload::cert_identity::CertificateIdentity {
            machine_id: proof.machine_id.clone(),
            machine_name: proof.machine_name.clone(),
            private_key: PRIVATE.clone(),
            certificate,
        };
        (identity, proof)
    }

    async fn write_identity(
        bundle: &Path,
        identity: &isideload::sideload::cert_identity::CertificateIdentity,
    ) {
        let mut info = plist::Dictionary::new();
        info.insert(
            "ALTCertificateID".into(),
            identity.get_serial_number().into(),
        );
        plist::to_file_xml(bundle.join("Info.plist"), &info).unwrap();
        let p12 = identity.as_p12(&identity.machine_id).await.unwrap();
        std::fs::write(bundle.join("ALTCertificate.p12"), p12).unwrap();
    }

    #[tokio::test]
    async fn validates_real_sdk_embedded_pkcs12_and_rejects_wrong_password_certificate_or_key() {
        let bundle = tempfile::tempdir().unwrap();
        let (mut identity, proof) = embedded_identity_fixture(0x42);
        write_identity(bundle.path(), &identity).await;
        verify_embedded_identity(bundle.path(), &proof).unwrap();

        let mut wrong_password = proof.clone();
        wrong_password.machine_id = "incorrect-password".into();
        has_code(
            verify_embedded_identity(bundle.path(), &wrong_password),
            "UNVERIFIED",
        );

        let mut wrong_key = proof.clone();
        wrong_key.public_key = b"different-public-key".to_vec();
        has_code(
            verify_embedded_identity(bundle.path(), &wrong_key),
            "CERTIFICATE-MISMATCH",
        );

        let (other_identity, _) = embedded_identity_fixture(0x43);
        write_identity(bundle.path(), &other_identity).await;
        has_code(
            verify_embedded_identity(bundle.path(), &proof),
            "CERTIFICATE-MISMATCH",
        );

        // Keep the pinned certificate but embed an unrelated private key.
        // Some PKCS#12 readers reject this while parsing; others expose both
        // objects. Neither path may allow upload as a usable AltStore identity.
        identity.private_key = RsaPrivateKey::new(&mut rand::thread_rng(), 2048).unwrap();
        write_identity(bundle.path(), &identity).await;
        assert!(verify_embedded_identity(bundle.path(), &proof).is_err());
    }

    #[tokio::test]
    async fn rejects_tampered_embedded_serial_archive_and_oversized_files() {
        let bundle = tempfile::tempdir().unwrap();
        let (identity, proof) = embedded_identity_fixture(0x42);
        write_identity(bundle.path(), &identity).await;
        let mut info = plist::Dictionary::new();
        info.insert("ALTCertificateID".into(), "43".into());
        plist::to_file_xml(bundle.path().join("Info.plist"), &info).unwrap();
        has_code(
            verify_embedded_identity(bundle.path(), &proof),
            "CERTIFICATE-MISMATCH",
        );
        write_identity(bundle.path(), &identity).await;
        std::fs::write(bundle.path().join("ALTCertificate.p12"), b"corrupt archive").unwrap();
        has_code(
            verify_embedded_identity(bundle.path(), &proof),
            "UNVERIFIED",
        );
        std::fs::write(
            bundle.path().join("ALTCertificate.p12"),
            vec![0; 1024 * 1024 + 1],
        )
        .unwrap();
        has_code(
            verify_embedded_identity(bundle.path(), &proof),
            "UNVERIFIED",
        );
        std::fs::write(bundle.path().join("Info.plist"), vec![0; 1024 * 1024 + 1]).unwrap();
        has_code(
            verify_embedded_identity(bundle.path(), &proof),
            "UNVERIFIED",
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn rejects_symlinked_embedded_identity_files() {
        let bundle = tempfile::tempdir().unwrap();
        let (identity, proof) = embedded_identity_fixture(0x42);
        write_identity(bundle.path(), &identity).await;
        let original = bundle.path().join("ALTCertificate.p12");
        let moved = bundle.path().join("other.p12");
        std::fs::rename(&original, &moved).unwrap();
        std::os::unix::fs::symlink(&moved, &original).unwrap();
        has_code(
            verify_embedded_identity(bundle.path(), &proof),
            "UNVERIFIED",
        );
    }
}
