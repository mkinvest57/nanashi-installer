use isideload::util::{keyring_storage::KeyringStorage, storage::SideloadingStorage};
use tauri::AppHandle;

use crate::error::AppError;

// Never share credentials, certificates or ADI state with the upstream installer.
pub const KEYRING_SERVICE: &str = "nanashi-installer";

#[tauri::command]
pub fn keyring_available() -> bool {
    // A unique, disposable entry avoids reading or replacing existing credentials.
    let Ok(entry) = keyring::Entry::new(
        KEYRING_SERVICE,
        &format!("availability-probe-{}", uuid::Uuid::new_v4()),
    ) else {
        return false;
    };
    if entry.set_password("nanashi-keyring-probe").is_err() {
        return false;
    }
    let available = entry
        .get_password()
        .is_ok_and(|value| value == "nanashi-keyring-probe");
    let removed = entry.delete_credential().is_ok();
    available && removed
}

fn require_secure_storage(available: bool) -> Result<(), AppError> {
    if available {
        Ok(())
    } else {
        Err(AppError::Keyring(
            "Le trousseau sécurisé est indisponible. Déverrouillez-le puis réessayez. Aucun secret ne sera enregistré dans un fichier.".into(),
        ))
    }
}

pub fn create_sideloading_storage(
    _app: &AppHandle,
) -> Result<Box<dyn SideloadingStorage>, AppError> {
    require_secure_storage(keyring_available())?;
    Ok(Box::new(KeyringStorage::new(KEYRING_SERVICE.to_string())))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_keyring_is_a_hard_failure() {
        assert!(matches!(
            require_secure_storage(false),
            Err(AppError::Keyring(_))
        ));
        assert!(require_secure_storage(true).is_ok());
    }

    #[test]
    fn namespace_does_not_reuse_upstream_credentials() {
        assert_eq!(KEYRING_SERVICE, "nanashi-installer");
        assert_ne!(KEYRING_SERVICE, "iloader");
    }
}
