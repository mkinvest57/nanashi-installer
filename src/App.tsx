import { useCallback, useEffect, useRef, useState } from "react";
import { getVersion } from "@tauri-apps/api/app";
import { invoke, isTauri } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { openUrl } from "@tauri-apps/plugin-opener";
import { FiArrowLeft, FiArrowRight, FiCheck, FiCopy, FiExternalLink, FiLock, FiShield, FiSmartphone } from "react-icons/fi";
import { AppleID } from "./AppleID";
import type { DeviceInfo } from "./Device";
import { isSupportedIOS, NanashiDevice } from "./components/NanashiDevice";
import { isInstallationUncertain, NanashiButton, NanashiError, NanashiGlass } from "./components/NanashiGlass";
import "./Nanashi.css";

const HANDOFF_URL = "https://nanashi-mk.vercel.app/installation-nanashi?step=iphone#installation-etape";
const STAGES = ["Votre iPhone", "Compte Apple", "Préparation", "Sur l’iPhone"];
const OPERATION_STEPS = [
  { id: "preflight", label: "Vérification de l’iPhone et du compte" },
  { id: "download", label: "Téléchargement d’AltStore Classic" },
  { id: "prepare", label: "Préparation de la signature" },
  { id: "install", label: "Installation d’AltStore sur l’iPhone" },
  { id: "pairing", label: "Association à cet iPhone" },
] as const;
type OperationUpdate = { updateType: "started" | "finished" | "failed"; stepId: string; extraDetails?: unknown };
type ManagerResult = {
  manager: "AltStore Classic"; managerVersion: string; managerBundleIdentifier: string; deviceName: string;
  pairingPlaced: true; nanashiInstalled: false; nextStep: "finish_on_iphone"; nanashiInstallUrl: string;
};
type BootstrapConfiguration = { manager: string; managerVersion: string; minimumIos: string };

function App() {
  const native = isTauri();
  const [stage, setStage] = useState(0);
  const [version, setVersion] = useState("");
  const [selectedDevice, setSelectedDevice] = useState<DeviceInfo | null>(null);
  const [loggedInAs, setLoggedInAs] = useState<string | null>(null);
  const [keyring, setKeyring] = useState<boolean | null>(null);
  const [configuration, setConfiguration] = useState<BootstrapConfiguration | null>(null);
  const [configurationError, setConfigurationError] = useState<unknown>(null);
  const [deviceBusy, setDeviceBusy] = useState(false);
  const [authBusy, setAuthBusy] = useState(false);
  const [installing, setInstalling] = useState(false);
  const [currentStep, setCurrentStep] = useState<string | null>(null);
  const [completed, setCompleted] = useState<string[]>([]);
  const [operationError, setOperationError] = useState<unknown>(null);
  const [requiresPhoneCheck, setRequiresPhoneCheck] = useState(false);
  const [result, setResult] = useState<ManagerResult | null>(null);
  const [linkStatus, setLinkStatus] = useState("");
  const busy = deviceBusy || authBusy || installing;
  const compatibleDevice = selectedDevice && configuration && isSupportedIOS(selectedDevice.version, configuration.minimumIos);
  const heading = useRef<HTMLHeadingElement>(null);
  const focusOnStep = useRef(false);
  const installLock = useRef(false);
  const mounted = useRef(true);
  const unlistenRef = useRef<(() => void) | null>(null);

  const checkKeyring = useCallback(async () => {
    setKeyring(null);
    try { setKeyring(await invoke<boolean>("keyring_available")); }
    catch { setKeyring(false); }
  }, []);
  const loadConfiguration = useCallback(async () => {
    try {
      const config = await invoke<BootstrapConfiguration>("nanashi_bootstrap_configuration");
      if (config.manager !== "AltStore Classic" || !/^\d+(?:\.\d+)*$/.test(config.minimumIos)) throw { type: "misc" };
      setConfiguration(config); setConfigurationError(null);
    } catch (failure) { setConfigurationError(failure); }
  }, []);

  useEffect(() => {
    mounted.current = true;
    if (native) { void checkKeyring(); void loadConfiguration(); void getVersion().then(setVersion).catch(() => {}); }
    return () => { mounted.current = false; unlistenRef.current?.(); };
  }, [native, checkKeyring, loadConfiguration]);
  useEffect(() => { if (focusOnStep.current) { heading.current?.focus(); focusOnStep.current = false; } }, [stage]);
  useEffect(() => { setResult(null); setCompleted([]); setOperationError(null); }, [selectedDevice?.udid, loggedInAs]);

  function navigate(next: number) {
    if (busy) return;
    focusOnStep.current = next !== stage;
    setStage(next);
  }
  function canVisit(next: number) {
    return !busy && (next === 0 || (next === 1 && compatibleDevice) || (next === 2 && compatibleDevice && loggedInAs !== null) || (next === 3 && result !== null));
  }
  async function openExternal(url: string) {
    try { await openUrl(url); setLinkStatus(""); }
    catch { setLinkStatus("L’ouverture n’a pas abouti. Copiez le lien pour l’ouvrir dans votre navigateur."); }
  }
  async function copyHandoff() {
    try { await navigator.clipboard.writeText(HANDOFF_URL); setLinkStatus("Lien copié."); }
    catch { setLinkStatus("Sélectionnez le lien ci-dessous pour le copier."); }
  }
  async function preparePhone() {
    if (installLock.current || busy || requiresPhoneCheck || !compatibleDevice || !loggedInAs || !keyring) return;
    installLock.current = true;
    setInstalling(true); setOperationError(null); setResult(null); setCompleted([]); setCurrentStep(null);
    try {
      const unlisten = await listen<OperationUpdate>("operation_install_nanashi_manager", event => {
        if (!mounted.current) return;
        const update = event.payload;
        if (!OPERATION_STEPS.some(step => step.id === update.stepId)) return;
        if (update.updateType === "started") setCurrentStep(update.stepId);
        if (update.updateType === "finished") setCompleted(previous => [...new Set([...previous, update.stepId])]);
        if (update.updateType === "failed") { setCurrentStep(update.stepId); setOperationError(update.extraDetails ?? { type: "misc" }); if (isInstallationUncertain(update.extraDetails)) setRequiresPhoneCheck(true); }
      });
      unlistenRef.current = unlisten;
      const outcome = await invoke<ManagerResult>("install_nanashi_manager_operation");
      if (!mounted.current) return;
      if (outcome.manager !== "AltStore Classic" || outcome.pairingPlaced !== true || outcome.nanashiInstalled !== false || outcome.nextStep !== "finish_on_iphone") throw { type: "misc", message: "Unverified preparation result" };
      setResult(outcome); setCompleted(OPERATION_STEPS.map(step => step.id)); setCurrentStep(null);
      focusOnStep.current = true; setStage(3);
    } catch (failure) { if (mounted.current) { setOperationError(failure); if (isInstallationUncertain(failure)) setRequiresPhoneCheck(true); } }
    finally {
      unlistenRef.current?.(); unlistenRef.current = null; installLock.current = false;
      if (mounted.current) setInstalling(false);
    }
  }

  return <main className="ni-shell">
    <header className="ni-header"><a className="ni-brand" href="https://nanashi-mk.vercel.app" onClick={event => { event.preventDefault(); void openExternal("https://nanashi-mk.vercel.app"); }}><img src="/nanashi.png" width="42" height="42" alt="" /><span>Nanashi<span className="ni-brand-dot">.</span><small>INSTALLATEUR</small></span></a><span className="ni-version">{version ? `v${version}` : "Installation iPhone"}</span></header>
    <section className="ni-intro"><p className="ni-eyebrow">Votre app. Sur votre iPhone.</p><h1>On prépare la suite.</h1><p>Branchez votre iPhone. L’ordinateur prépare AltStore, puis vous terminez l’installation de Nanashi sur le téléphone.</p></section>

    {!native ? <NanashiGlass className="ni-stage"><h2>Ouvrez l’application Nanashi Installer</h2><p>La connexion Apple et la détection de l’iPhone fonctionnent uniquement dans l’application pour ordinateur.</p><p>Aucun identifiant ne peut être saisi dans cet aperçu web.</p></NanashiGlass> : <div className="ni-layout">
      <aside className="ni-sidebar"><nav aria-label="Étapes de l’installation">{STAGES.map((label, index) => <button key={label} type="button" aria-current={stage === index ? "step" : undefined} disabled={!canVisit(index)} onClick={() => navigate(index)}><span className="ni-step-number">{index < stage ? <FiCheck aria-hidden="true" /> : index + 1}</span><span>{label}</span></button>)}</nav><div className="ni-side-note"><FiShield aria-hidden="true" /><p>Gardez votre Nanashi actuelle et son historique pendant la préparation.</p></div></aside>
      <NanashiGlass className="ni-stage" aria-labelledby="ni-stage-title">
        <div className="ni-stage-meta"><span>ÉTAPE {stage + 1} / 4</span><span>{stage === 3 ? "SUR L’IPHONE" : "SUR L’ORDINATEUR"}</span></div>
        <h2 ref={heading} id="ni-stage-title" tabIndex={-1}>{STAGES[stage]}</h2>

        {stage === 0 && <><p className="ni-description">Branchez l’iPhone en USB et déverrouillez-le. Sélectionnez-le ci-dessous lorsqu’il apparaît.{configuration && <> Cette préparation avec AltStore nécessite iOS {configuration.minimumIos} ou plus récent.</>}</p>{configurationError !== null && <><NanashiError error={configurationError} /><button type="button" className="ni-text-button" onClick={() => void loadConfiguration()}>Recharger la configuration</button></>}<NanashiDevice selectedDevice={selectedDevice} onSelect={setSelectedDevice} onBusyChange={setDeviceBusy} minimumIos={configuration?.minimumIos} /><details className="ni-help"><summary>L’iPhone n’apparaît pas ?</summary><p>Acceptez « Faire confiance à cet ordinateur » sur l’iPhone. Essayez un autre port USB ou un câble qui transporte les données. Sur Windows, installez <a href="https://apps.microsoft.com/detail/9np83lwlpz9k" onClick={event => { event.preventDefault(); void openExternal("https://apps.microsoft.com/detail/9np83lwlpz9k"); }}>Appareils Apple</a>, puis relancez la détection.</p></details><div className="ni-actions"><NanashiButton primary type="button" disabled={!compatibleDevice || busy} onClick={() => navigate(1)}>Continuer<FiArrowRight aria-hidden="true" /></NanashiButton></div></>}

        {stage === 1 && <><p className="ni-description">Utilisez le même compte Apple que pour votre Nanashi actuelle. Il sert à signer l’app pour votre iPhone.</p>{keyring === null && <p role="status">Vérification du trousseau sécurisé…</p>}<AppleID loggedInAs={loggedInAs} setLoggedInAs={setLoggedInAs} noKeyringAvailable={keyring === false} disabled={keyring === null} onBusyChange={setAuthBusy} onCheckKeyring={() => void checkKeyring()} /><div className="ni-actions"><button className="ni-text-button" type="button" disabled={busy} onClick={() => navigate(0)}><FiArrowLeft aria-hidden="true" />Retour</button><NanashiButton primary type="button" disabled={!loggedInAs || busy || !keyring} onClick={() => navigate(2)}>Continuer<FiArrowRight aria-hidden="true" /></NanashiButton></div></>}

        {stage === 2 && <><p className="ni-description">Nous installons AltStore Classic sur {selectedDevice?.name ?? "votre iPhone"} et préparons son association. Nanashi sera installée à l’étape suivante, sur le téléphone.</p>
          <div className="ni-install-summary"><FiSmartphone aria-hidden="true" /><div><strong>{selectedDevice?.name}</strong><span>AltStore Classic · préparation de l’installation</span></div><FiLock aria-hidden="true" /></div>
          {!installing && !completed.length && <details className="ni-help"><summary>Nanashi est déjà installée ?</summary><p>Conservez la copie existante et faites une sauvegarde récente depuis Nanashi. Gardez le même compte Apple. Si une nouvelle copie apparaît ensuite, n’effacez pas l’ancienne : l’historique ne se transfère pas automatiquement.</p></details>}
          {(installing || completed.length > 0 || operationError !== null) && <ol className="ni-operation" aria-label="Progression de la préparation">{OPERATION_STEPS.map(step => <li key={step.id} className={completed.includes(step.id) ? "ni-done" : currentStep === step.id ? "ni-current" : ""}><span className="ni-operation-dot" aria-hidden="true">{completed.includes(step.id) ? <FiCheck /> : ""}</span><span>{step.label}</span>{currentStep === step.id && !completed.includes(step.id) && <small>{operationError ? "Interrompu" : "En cours"}</small>}</li>)}</ol>}
          {installing && <p className="ni-notice" role="status">Gardez l’iPhone branché et déverrouillé. Fermer cette fenêtre n’annule pas une installation déjà commencée.</p>}
          {operationError !== null && <>{completed.includes("install") && <div className="ni-notice"><strong>AltStore est installé, mais sa préparation reste incomplète.</strong><p>L’association à l’iPhone n’a pas été confirmée. Nanashi n’a pas été installée par cette opération.</p></div>}<NanashiError error={operationError} /></>}
          {requiresPhoneCheck && <div className="ni-notice"><p>La vérification sur l’iPhone est nécessaire avant tout nouvel essai. Ce bouton confirme votre vérification ; il ne relance rien.</p><NanashiButton type="button" disabled={installing} onClick={() => setRequiresPhoneCheck(false)}>J’ai vérifié l’état sur l’iPhone</NanashiButton></div>}
          <div className="ni-actions"><button className="ni-text-button" type="button" disabled={busy} onClick={() => navigate(1)}><FiArrowLeft aria-hidden="true" />Retour</button><NanashiButton primary type="button" disabled={busy || requiresPhoneCheck || !selectedDevice || !loggedInAs || !keyring} onClick={() => void preparePhone()}>{installing ? "Préparation en cours…" : operationError ? "Réessayer la préparation" : "Préparer mon iPhone"}<FiArrowRight aria-hidden="true" /></NanashiButton></div>
        </>}

        {stage === 3 && result && <><div className="ni-success"><FiCheck aria-hidden="true" /><div><strong>AltStore est prêt sur {result.deviceName}.</strong><p>L’association est en place. Il reste à autoriser AltStore et à installer Nanashi sur l’iPhone.</p></div></div>
          <div className="ni-handoff"><img src="/nanashi-iphone-qr.svg" alt="QR code pour terminer l’installation Nanashi sur l’iPhone" width="168" height="168" /><div><h3>Prenez votre iPhone.</h3><p>Scannez ce code avec son appareil photo. Le guide Nanashi vous accompagne pour les dernières validations.</p><NanashiButton type="button" onClick={() => void copyHandoff()}><FiCopy aria-hidden="true" />Copier le lien</NanashiButton></div></div>
          <ol className="ni-phone-steps"><li>Autorisez le profil développeur et activez le Mode développeur si iOS le demande.</li><li>Dans AltStore, terminez l’assistant de connexion à distance, préparez le VPN demandé et connectez-vous avec le même compte Apple.</li><li>Depuis le guide Nanashi, lancez l’installation et validez-la sur l’iPhone.</li></ol>
          <a className="ni-readable-link" href={HANDOFF_URL} onClick={event => { event.preventDefault(); void openExternal(HANDOFF_URL); }}>{HANDOFF_URL}<FiExternalLink aria-hidden="true" /></a>
          <details className="ni-help"><summary>Et pour les prochains renouvellements ?</summary><p>Un compte Apple gratuit signe les apps pour 7 jours. Le guide explique comment configurer le renouvellement sur l’iPhone. Il dépend encore de la connexion, du VPN et de la session Apple : une intervention peut parfois rester nécessaire.</p></details>
        </>}
      </NanashiGlass>
    </div>}
    <p className="ni-link-status" role="status">{linkStatus}</p>
    <footer className="ni-footer"><span>Une adaptation indépendante d’iloader.</span><a href="https://github.com/nab138/iloader" onClick={event => { event.preventDefault(); void openExternal("https://github.com/nab138/iloader"); }}>Projet d’origine<FiExternalLink aria-hidden="true" /></a></footer>
  </main>;
}
export default App;
