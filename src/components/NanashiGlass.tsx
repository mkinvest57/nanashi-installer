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

export function installationError(error: unknown): { title: string; message: string; code?: string } {
  const object = error && typeof error === "object" ? error as Record<string, unknown> : {};
  const message = typeof object.message === "string" ? object.message : typeof error === "string" ? error : "";
  const code = message.match(/-\d{4,6}\b/)?.[0];
  if (message.includes("La limite de certificats Apple est atteinte")) return {
    title: "Limite de certificats Apple atteinte",
    message: "La préparation s’est arrêtée pour préserver vos autres apps. Aucun certificat ni profil existant n’a été révoqué. Conservez votre installation actuelle : cette limite doit être résolue avant de reprendre.",
  };
  if (code === "-80045") return { title: "Apple a refusé la connexion", message: "La préparation ne peut pas continuer avec cette session. Aucun nouvel essai automatique n’est lancé. Vérifiez les demandes Apple sur vos appareils, puis réessayez une seule fois depuis la connexion.", code };
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
  return { ...(known ?? { title: "La préparation s’est arrêtée", message: "Vérifiez la connexion de l’iPhone et votre session Apple avant de réessayer. L’installateur ne relance pas l’opération tout seul." }), ...(code ? { code } : {}) };
}
export function NanashiError({ error }: { error: unknown }) {
  const detail = installationError(error);
  return <div className="ni-error" role="alert"><strong>{detail.title}{detail.code ? ` (${detail.code})` : ""}</strong><p>{detail.message}</p></div>;
}
