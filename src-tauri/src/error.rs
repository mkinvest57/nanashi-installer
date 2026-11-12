use idevice::IdeviceError;
use isideload::SideloadError;
use rootcause::Report;
use serde::Serialize;
use serde::ser::{SerializeStruct, Serializer};

#[derive(Debug, thiserror::Error, Clone, strum::AsRefStr)]
#[strum(serialize_all = "snake_case")]
pub enum AppError {
    #[error("{0}")]
    MaxApps(String),
    #[error("{0}")]
    NotEnoughAppIds(String),
    #[error("{0}")]
    DeviceComs(String),
    #[error("{0}")]
    InstallationUncertain(String),
    #[error("{0}")]
    InstallationFailed(String),
    #[error("{0}")]
    Underage(String),
    #[error("{0}")]
    AccountLocked(String),
    #[error("{0}")]
    Developer(String),
    #[error("{0}")]
    Auth(String),
    #[error("{0}")]
    Download(String),
    #[error("{0}: {1}")]
    HouseArrest(String, String),
    #[error("{0}")]
    RemotePairing(String),
    #[error("{0}: {1}")]
    LockdownPairing(String, String),
    #[error("{0} canceled")]
    Canceled(String),
    #[error("Failed to emit status to frontend: {0}")]
    OperationUpdate(String),
    #[error("{0}: {1}")]
    DeviceComsWithMessage(String, String),
    #[error("{0}: {1}")]
    Usbmuxd(String, String),
    #[error("Not logged in")]
    NotLoggedIn,
    #[error("No device selected")]
    NoDeviceSelected,
    #[error("{0}")]
    Anisette(String),
    #[error("{0}")]
    Keyring(String),
    #[error("Keyring error: {0} - {1}")]
    KeyringWithMessage(String, String),
    #[error("{0}: {1}")]
    Storage(String, String),
    #[error("{0}")]
    Misc(String),
    #[error("{0}: {1}")]
    Filesystem(String, String),
}

impl Serialize for AppError {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("AppError", 2)?;
        state.serialize_field("type", self.as_ref())?;
        state.serialize_field("message", &self.to_string())?;
        state.end()
    }
}

// Signing/installation reports are not authentication failures. Preserve typed
// causes and fixed SDK stage names without exposing request bodies or paths.
pub(crate) fn safe_installation_error(report: Report) -> AppError {
    for cause in report.iter_reports() {
        if let Some(marker) =
            cause.downcast_current_context::<crate::account::CertificatesPreserved>()
        {
            return AppError::Developer(marker.to_string());
        }
        if cause.downcast_current_context::<keyring::Error>().is_some() {
            return AppError::Keyring("Le trousseau n’a pas permis d’accéder à la clé de signature. Déverrouillez-le avant de reprendre. Les certificats existants sont conservés.".into());
        }
        if let Some(error) = cause.downcast_current_context::<SideloadError>() {
            match error {
                SideloadError::AuthWithMessage(code, _) => {
                    return AppError::Auth(format!(
                        "Apple a refusé la session pendant la préparation ({code}). Aucun nouvel essai automatique n’a été lancé."
                    ));
                }
                SideloadError::DeveloperError(7460, _) => {
                    return AppError::Developer(crate::account::CertificatesPreserved.to_string());
                }
                SideloadError::DeveloperError(code, _) => {
                    return AppError::Developer(format!(
                        "Le service développeur Apple a refusé la signature ({code}). Aucun certificat existant n’a été révoqué."
                    ));
                }
                SideloadError::IdeviceError(error) => return safe_device_installation_error(error),
                SideloadError::InvalidBundle(_) => {
                    return AppError::InstallationFailed(
                        "Le moteur n’a pas pu préparer l’archive AltStore. Code : INSTALL-ARCHIVE."
                            .into(),
                    );
                }
                _ => {}
            }
        }
        if let Some(error) = cause.downcast_current_context::<IdeviceError>() {
            return safe_device_installation_error(error);
        }
        if cause.downcast_current_context::<reqwest::Error>().is_some() {
            return AppError::InstallationFailed("La communication réseau s’est interrompue pendant la signature. Vérifiez votre connexion Internet. Aucun nouvel essai automatique n’est lancé. Code : INSTALL-NETWORK.".into());
        }
    }

    for cause in report.iter_reports() {
        let context = cause
            .downcast_current_context::<String>()
            .map(String::as_str)
            .or_else(|| cause.downcast_current_context::<&'static str>().copied());
        match context {
            Some("Failed to retrieve certificate identity") => return AppError::InstallationFailed("La préparation du certificat de signature a échoué. Les certificats existants sont conservés. Code : INSTALL-CERTIFICATE.".into()),
            Some("Failed to modify app bundle") => return AppError::InstallationFailed("La préparation d’AltStore avant signature a échoué. Code : INSTALL-ARCHIVE.".into()),
            Some("Failed to sign app") => return AppError::InstallationFailed("La signature d’AltStore a échoué avant son transfert sur l’iPhone. Code : INSTALL-SIGNATURE.".into()),
            Some(message) if message.starts_with("Not enough available app IDs") => return AppError::NotEnoughAppIds("La limite d’identifiants Apple est atteinte. Aucun identifiant existant n’a été supprimé.".into()),
            _ => {}
        }
    }
    unknown_installation_result()
}

fn unknown_installation_result() -> AppError {
    AppError::InstallationUncertain("L’installateur n’a pas pu confirmer le résultat sur l’iPhone. Ne supprimez aucune app et vérifiez AltStore sur l’iPhone avant de reprendre. Aucun nouvel essai automatique n’est lancé.".into())
}

fn safe_device_installation_error(error: &IdeviceError) -> AppError {
    use idevice::installation_proxy::InstallationProxyError;
    match error {
        IdeviceError::ApplicationVerificationFailed(message)
        | IdeviceError::InstallationProxy(InstallationProxyError::OperationFailed(message)) => {
            if message.contains("maximum number of installed apps") {
                AppError::MaxApps("La limite d’apps de développement est atteinte. Conservez Nanashi et son historique.".into())
            } else {
                AppError::InstallationFailed("iOS a refusé l’installation d’AltStore. Aucune app existante n’a été supprimée. Gardez l’iPhone déverrouillé et vérifiez son Mode développeur. Code : INSTALL-IOS.".into())
            }
        }
        IdeviceError::DeviceLocked => AppError::InstallationFailed("L’iPhone est verrouillé. Déverrouillez-le et vérifiez son écran avant de reprendre. Code : INSTALL-LOCKED.".into()),
        IdeviceError::DeveloperModeNotEnabled => AppError::InstallationFailed("Activez le Mode développeur dans Réglages → Confidentialité et sécurité sur l’iPhone, puis redémarrez-le et confirmez. Code : INSTALL-DEVELOPER-MODE.".into()),
        _ => unknown_installation_result(),
    }
}

// from rootcause report
impl From<Report> for AppError {
    fn from(report: Report) -> Self {
        let report_str = report.to_string();

        for cause in report.iter_reports() {
            if cause.downcast_current_context::<keyring::Error>().is_some() {
                return AppError::Keyring(report_str);
            }
            if let Some(err) = cause.downcast_current_context::<SideloadError>() {
                match err {
                    &SideloadError::AuthWithMessage(code, _) => match code {
                        -20209 => return AppError::AccountLocked(report_str),
                        _ => {
                            return AppError::Auth(report_str);
                        }
                    },
                    &SideloadError::DeveloperError(code, _) => match code {
                        1102 => return AppError::Underage(report_str),
                        _ => {
                            return AppError::Developer(report_str);
                        }
                    },
                    SideloadError::IdeviceError(idev_err) => match idev_err {
                        IdeviceError::Socket(_) => {
                            return AppError::DeviceComs(report_str);
                        }
                        IdeviceError::ApplicationVerificationFailed(e) => {
                            if e.contains("maximum number of installed apps") {
                                return AppError::MaxApps(report_str);
                            }
                        }
                        _ => {}
                    },
                    _ => {}
                }
            }
            let cause_str = cause.to_string();
            if cause_str.contains("Not enough available app IDs") {
                return AppError::NotEnoughAppIds(report_str);
            }
            if cause_str.contains("Failed to get anisette data for login")
                || cause_str.contains("Failed to get anisette client info")
                || cause_str.contains("Failed to get anisette headers")
            {
                return AppError::Anisette(report_str);
            }
        }

        AppError::Misc(report_str)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rootcause::prelude::*;

    fn wrapped<E: std::error::Error + Send + Sync + 'static>(error: E) -> Report {
        Err::<(), _>(error)
            .context("private-request-context")
            .unwrap_err()
            .into()
    }

    #[test]
    fn certificate_limit_does_not_become_an_authentication_error() {
        let error = safe_installation_error(wrapped(crate::account::CertificatesPreserved));
        assert!(matches!(error, AppError::Developer(_)));
        assert!(
            error
                .to_string()
                .contains("La limite de certificats Apple est atteinte")
        );
        assert!(!error.to_string().contains("private-request-context"));
    }

    #[test]
    fn apple_refusals_preserve_only_numeric_codes_and_categories() {
        for (source, expected) in [
            (
                SideloadError::AuthWithMessage(-80045, "private-response".into()),
                "auth",
            ),
            (
                SideloadError::DeveloperError(9412, "private-response".into()),
                "developer",
            ),
        ] {
            let error = safe_installation_error(wrapped(source));
            assert_eq!(error.as_ref(), expected);
            assert!(!error.to_string().contains("private-response"));
            assert!(!error.to_string().contains("private-request-context"));
        }
        let error = safe_installation_error(wrapped(SideloadError::DeveloperError(
            7460,
            "private".into(),
        )));
        assert!(
            error
                .to_string()
                .contains("La limite de certificats Apple est atteinte")
        );
    }

    #[test]
    fn missing_transport_completion_is_uncertain_but_explicit_ios_rejection_is_not() {
        let disconnected = safe_installation_error(wrapped(SideloadError::IdeviceError(
            IdeviceError::Socket(std::io::Error::other("private-device-detail")),
        )));
        assert!(matches!(disconnected, AppError::InstallationUncertain(_)));
        let rejected = safe_installation_error(wrapped(SideloadError::IdeviceError(
            IdeviceError::ApplicationVerificationFailed("private-certificate-detail".into()),
        )));
        assert!(matches!(rejected, AppError::InstallationFailed(_)));
        let quota = safe_installation_error(wrapped(SideloadError::IdeviceError(
            IdeviceError::ApplicationVerificationFailed(
                "maximum number of installed apps; private-detail".into(),
            ),
        )));
        assert!(matches!(quota, AppError::MaxApps(_)));
        for error in [disconnected, rejected, quota] {
            assert!(!error.to_string().contains("private-"));
        }
    }

    #[test]
    fn fixed_sdk_stage_survives_without_exporting_a_private_error() {
        let report = Err::<(), _>(std::io::Error::other("private-path-and-response"))
            .context("Failed to sign app")
            .unwrap_err();
        let error = safe_installation_error(report.into());
        assert!(matches!(error, AppError::InstallationFailed(_)));
        assert!(error.to_string().contains("INSTALL-SIGNATURE"));
        assert!(!error.to_string().contains("private-"));
        let unknown = safe_installation_error(wrapped(std::io::Error::other("private-unknown")));
        assert!(matches!(unknown, AppError::InstallationUncertain(_)));
        assert!(!unknown.to_string().contains("private-"));
    }

    #[test]
    fn keyring_failure_remains_a_local_storage_failure() {
        let error = safe_installation_error(wrapped(keyring::Error::NoEntry));
        assert!(matches!(error, AppError::Keyring(_)));
        assert!(!error.to_string().contains("private-request-context"));
    }
}
