import type { ButtonHTMLAttributes, HTMLAttributes, ReactNode } from "react";

// Reused from Nanashi's documented 21st adaptations:
// https://21st.dev/@educalvolpz/components/glass-card
// https://21st.dev/@jahed/components/glass-button
// Static optical layers require no pointer tracking or animation runtime.
export function NanashiGlass({ className = "", ...props }: HTMLAttributes<HTMLDivElement>) {
  return <div className={`ni-glass ${className}`} {...props} />;
}
export function NanashiButton({ className = "", primary = false, children, ...props }: ButtonHTMLAttributes<HTMLButtonElement> & { primary?: boolean; children: ReactNode }) {
  return <button className={`ni-button ${primary ? "ni-primary" : ""} ${className}`} {...props}><span>{children}</span></button>;
}
export function isInstallationUncertain(error: unknown): boolean {
  return Boolean(error && typeof error === "object" && "type" in error && error.type === "installation_uncertain");
}

// Only fixed native diagnostic markers select copy; never render a report body.
const installationDiagnostics: Record<string, { title: string; message: string }> = {
  "INSTALL-ARCHIVE": { title: "L’archive AltStore n’a pas pu être préparée", message: "La préparation de l’archive s’est arrêtée avant l’installation. Conservez vos apps existantes. Aucun nouvel essai automatique n’est lancé." },
  "INSTALL-NETWORK": { title: "La signature a été interrompue par le réseau", message: "Vérifiez la connexion Internet de l’ordinateur avant de reprendre. Aucun nouvel essai automatique n’est lancé." },
  "INSTALL-CERTIFICATE": { title: "Le certificat de signature n’a pas pu être préparé", message: "La préparation du certificat a échoué. Les certificats existants sont conservés ; ne révoquez pas ceux de vos autres apps pour contourner cette erreur." },
  "INSTALL-SIGNATURE": { title: "La signature d’AltStore a échoué", message: "La signature s’est arrêtée avant le transfert sur l’iPhone. Conservez vos apps existantes. Aucun nouvel essai automatique n’est lancé." },
  "INSTALL-IOS": { title: "iOS a refusé l’installation d’AltStore", message: "Gardez l’iPhone déverrouillé et vérifiez son Mode développeur. Aucune app existante n’a été supprimée. Aucun nouvel essai automatique n’est lancé." },
  "INSTALL-LOCKED": { title: "L’iPhone est verrouillé", message: "Déverrouillez l’iPhone et vérifiez son écran avant de reprendre la préparation." },
  "INSTALL-DEVELOPER-MODE": { title: "Le Mode développeur est nécessaire", message: "Sur l’iPhone, ouvrez Réglages → Confidentialité et sécurité → Mode développeur. Activez-le, puis redémarrez et confirmez si demandé." },
};

export function installationError(error: unknown): { title: string; message: string; code?: string } {
  const object = error && typeof error === "object" ? error as Record<string, unknown> : {};
  const message = typeof object.message === "string" ? object.message : typeof error === "string" ? error : "";
  const appleError = ["auth", "developer", "account_locked", "underage"].includes(String(object.type));
  const code = appleError ? message.match(/\((-?\d{1,10})\)/)?.[1] ?? message.match(/-\d{4,6}\b/)?.[0] : undefined;
  if (isInstallationUncertain(error)) return {
    title: "L’état de l’installation reste à vérifier",
    message: "Le résultat de l’installation n’a pas pu être confirmé ; l’iPhone peut encore terminer. Gardez vos apps et vérifiez AltStore sur l’iPhone avant de relancer. Nanashi n’a pas été installée par cette opération.",
  };
  if (object.type === "installation_failed") {
    const marker = message.match(/\bCode\s*:\s*(INSTALL-[A-Z-]+)\b/)?.[1];
    const detail = marker ? installationDiagnostics[marker] : undefined;
    return detail ? { ...detail, code: marker } : {
      title: "L’installation d’AltStore a échoué",
      message: "L’installation n’a pas abouti. Gardez vos apps et vérifiez les indications sur l’iPhone. Aucun nouvel essai automatique n’est lancé.",
    };
  }
  if (message.includes("La limite de certificats Apple est atteinte")) return {
    title: "Limite de certificats Apple atteinte",
    message: "La préparation s’est arrêtée pour préserver vos autres apps. Aucun certificat ni profil existant n’a été révoqué. Conservez votre installation actuelle : cette limite doit être résolue avant de reprendre.",
    ...(code ? { code } : {}),
  };
  if (object.type === "auth" && code === "-80045") return { title: "Apple a refusé la connexion", message: "La préparation ne peut pas continuer avec cette session. Aucun nouvel essai automatique n’est lancé. Vérifiez les demandes Apple sur vos appareils, puis réessayez une seule fois depuis la connexion.", code };
  const messages: Record<string, { title: string; message: string }> = {
    keyring: { title: "Le trousseau est indisponible", message: "Déverrouillez le trousseau de cet ordinateur avant de vous connecter. Les identifiants ne seront pas enregistrés dans un fichier de secours." },
    keyring_with_message: { title: "Le trousseau est indisponible", message: "Déverrouillez le trousseau de cet ordinateur, puis vérifiez à nouveau sa disponibilité." },
    auth: { title: "La connexion Apple n’a pas abouti", message: "Vérifiez vos identifiants et les demandes de validation Apple. Vous pouvez corriger les champs et relancer vous-même la connexion." },
    account_locked: { title: "Le compte Apple demande votre attention", message: "Terminez la vérification du compte sur votre appareil Apple avant de réessayer ici." },
    anisette: { title: "Le service de connexion est indisponible", message: "La connexion n’a pas pu être préparée. Vérifiez votre accès à Internet, puis réessayez plus tard. Aucune boucle de connexion n’est lancée." },
    download: { title: "Le téléchargement n’a pas abouti", message: "Vérifiez votre connexion Internet. Vous pourrez relancer la préparation lorsque le téléchargement sera accessible." },
    device_coms: { title: "L’iPhone ne répond plus", message: "Gardez-le déverrouillé et branché. Vérifiez le câble et la demande « Faire confiance », puis réessayez." },
    device_coms_with_message: { title: "L’iPhone ne répond plus", message: "Gardez-le déverrouillé et branché. Vérifiez le câble et la demande « Faire confiance », puis réessayez." },
    no_device_selected: { title: "Sélectionnez votre iPhone", message: "Revenez à la première étape pour vérifier sa connexion." },
    not_logged_in: { title: "Connectez-vous à Apple", message: "La session n’est plus disponible. Revenez à l’étape Compte Apple." },
    developer: { title: "La signature Apple demande une vérification", message: "La préparation s’est arrêtée. Aucun certificat ne sera révoqué automatiquement. Gardez le même compte que pour votre installation actuelle." },
    max_apps: { title: "La limite d’apps de développement est atteinte", message: "La préparation s’est arrêtée. Ne supprimez pas Nanashi pour libérer une place sans avoir sauvegardé son historique." },
    not_enough_app_ids: { title: "La limite d’identifiants Apple est atteinte", message: "Attendez qu’un emplacement redevienne disponible. L’installateur ne supprime pas vos identifiants existants." },
    canceled: { title: "Opération annulée", message: "Vous pouvez reprendre lorsque vous êtes prêt." },
  };
  const known = typeof object.type === "string" ? messages[object.type] : undefined;
  return { ...(known ?? { title: "La préparation s’est arrêtée", message: "Gardez vos apps et vérifiez les indications sur l’iPhone avant de reprendre. L’installateur ne relance pas l’opération tout seul." }), ...(code ? { code } : {}) };
}
export function NanashiError({ error }: { error: unknown }) {
  const detail = installationError(error);
  return <div className="ni-error" role="alert"><strong>{detail.title}{detail.code ? ` (${detail.code})` : ""}</strong><p>{detail.message}</p></div>;
}
