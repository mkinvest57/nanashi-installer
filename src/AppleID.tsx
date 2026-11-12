import { useEffect, useRef, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { emit, listen } from "@tauri-apps/api/event";
import { FiCheck, FiLock } from "react-icons/fi";
import { NanashiButton, NanashiError } from "./components/NanashiGlass";

const ANISETTE_SERVER = "https://mac-ani.jkcoxson.com";
type AppleChallenge = { requestId: string; unknown: boolean; sms: boolean; numbers: { id: number; label: string }[]; selectedNumberId: number | null; hasError: boolean };

export const AppleID = ({ loggedInAs, setLoggedInAs, noKeyringAvailable, disabled = false, onBusyChange, onCheckKeyring }: {
  loggedInAs: string | null; setLoggedInAs: (id: string | null) => void; noKeyringAvailable: boolean;
  disabled?: boolean; onBusyChange: (busy: boolean) => void; onCheckKeyring: () => void;
}) => {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [ready, setReady] = useState(false);
  const [canceling, setCanceling] = useState(false);
  const [code, setCode] = useState("");
  const [codeSent, setCodeSent] = useState(false);
  const [challenge, setChallenge] = useState<AppleChallenge | null>(null);
  const needsCode = challenge !== null && !challenge.unknown;
  const [challengeSending, setChallengeSending] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const attempt = useRef(0);
  const active = useRef(false);
  const mounted = useRef(true);
  const codeInput = useRef<HTMLInputElement>(null);
  const deviceMethod = useRef<HTMLButtonElement>(null);
  const responseInFlight = useRef(false);
  const pendingLogin = useRef<Promise<unknown> | null>(null);

  function setWorking(value: boolean) { active.current = value; setBusy(value); onBusyChange(value); }
  useEffect(() => {
    mounted.current = true;
    let disposed = false;
    let unlisten: (() => void) | undefined;
    async function prepare() {
      try {
        const remove = await listen<AppleChallenge>("2fa-required", event => {
          if (!disposed && active.current) {
            const request = event.payload;
            if (!request || typeof request.requestId !== "string" || typeof request.unknown !== "boolean" || !Array.isArray(request.numbers)) {
              setError({ type: "auth", message: "Unsupported verification request" });
              return;
            }
            setChallenge(request); setCode(""); setCodeSent(false);
            setChallengeSending(false); responseInFlight.current = false;
          }
        });
        if (disposed) { remove(); return; }
        unlisten = remove;
        const account = await invoke<string | null>("logged_in_as");
        if (!disposed) { setLoggedInAs(account); setReady(true); }
      } catch (failure) { if (!disposed) setError(failure); }
    }
    void prepare();
    return () => {
      disposed = true; mounted.current = false; unlisten?.(); attempt.current += 1;
      if (active.current) void invoke("cancel_login").catch(() => {});
      active.current = false; onBusyChange(false);
    };
  }, [setLoggedInAs, onBusyChange]);
  useEffect(() => { if (needsCode) codeInput.current?.focus(); }, [needsCode, challenge?.requestId]);
  useEffect(() => { if (challenge?.unknown) deviceMethod.current?.focus(); }, [challenge]);

  async function login() {
    if (active.current || disabled || noKeyringAvailable || !ready || !email.trim() || !password) return;
    const request = ++attempt.current;
    setError(null); setCodeSent(false); setChallenge(null); setWorking(true);
    try {
      const pending = invoke("login_new", { email: email.trim(), password, saveCredentials: false, anisetteServer: ANISETTE_SERVER });
      pendingLogin.current = pending;
      setPassword("");
      await pending;
      if (!mounted.current || request !== attempt.current) return;
      const account = await invoke<string | null>("logged_in_as");
      if (!account) throw { type: "auth", message: "Session unavailable" };
      if (mounted.current && request === attempt.current) setLoggedInAs(account);
    } catch (failure) { if (mounted.current && request === attempt.current) setError(failure); }
    finally {
      if (mounted.current && request === attempt.current) { pendingLogin.current = null; setWorking(false); setChallenge(null); setCode(""); setPassword(""); }
    }
  }
  async function cancelLogin() {
    attempt.current += 1;
    setCanceling(true);
    try {
      await invoke("cancel_login");
      // Cancellation is a request; the native login must release its lock first.
      await pendingLogin.current?.catch(() => undefined);
      pendingLogin.current = null;
      setWorking(false); setChallenge(null); setCode(""); setPassword("");
    }
    catch (failure) { setError(failure); }
    finally { setCanceling(false); }
  }
  async function sendCode() {
    if (!/^\d{6}$/.test(code) || canceling || !challenge || challenge.unknown || responseInFlight.current) return;
    const requestId = challenge.requestId, submittedCode = code;
    responseInFlight.current = true; setChallengeSending(true);
    setCode(""); setCodeSent(true);
    try { await emit("2fa-recieved", { requestId, action: "submit-code", code: submittedCode }); setChallenge(current => current?.requestId === requestId ? null : current); }
    catch (failure) { setError(failure); }
    finally { responseInFlight.current = false; setChallengeSending(false); }
  }
  async function requestCode(action: "request-device-code" | "request-sms-code", phoneId?: number) {
    if (!challenge?.unknown || canceling || responseInFlight.current) return;
    const requestId = challenge.requestId;
    responseInFlight.current = true; setChallengeSending(true);
    try { await emit("2fa-recieved", { requestId, action, ...(phoneId !== undefined ? { phoneId } : {}) }); setChallenge(current => current?.requestId === requestId ? null : current); }
    catch (failure) { setError(failure); }
    finally { responseInFlight.current = false; setChallengeSending(false); }
  }
  async function signOut() {
    setWorking(true); setError(null);
    try { await invoke("invalidate_account"); setLoggedInAs(null); setPassword(""); }
    catch (failure) { setError(failure); }
    finally { setWorking(false); }
  }

  return <div className="ni-account">
    {noKeyringAvailable && <div className="ni-error" role="alert"><strong>Déverrouillez le trousseau de l’ordinateur</strong><p>Il protège les éléments de signature Apple, même sans enregistrer le mot de passe. La connexion reste bloquée tant qu’il est indisponible.</p><NanashiButton type="button" onClick={onCheckKeyring} disabled={disabled}>Vérifier le trousseau</NanashiButton></div>}
    {loggedInAs ? <div className="ni-notice ni-account-connected"><FiCheck aria-hidden="true" /><div><strong>Compte Apple connecté</strong><p>{loggedInAs}</p><button className="ni-text-button" disabled={disabled || busy} type="button" onClick={() => void signOut()}>Utiliser un autre compte</button></div></div>
      : <form className="ni-login-form" onSubmit={event => { event.preventDefault(); void login(); }}>
        <label htmlFor="apple-email">Compte Apple<input id="apple-email" name="apple-email" type="text" inputMode="email" autoComplete="username" autoCapitalize="none" spellCheck={false} value={email} onChange={event => setEmail(event.target.value)} disabled={disabled || busy || noKeyringAvailable} placeholder="Votre adresse e-mail ou numéro" required /></label>
        <label htmlFor="apple-password">Mot de passe<input id="apple-password" name="apple-password" type="password" autoComplete="current-password" value={password} onChange={event => setPassword(event.target.value)} disabled={disabled || busy || noKeyringAvailable} required /></label>
        <p className="ni-caption"><FiLock aria-hidden="true" />Le mot de passe n’est pas mémorisé. La validation Apple peut demander un code sur votre appareil.</p>
        {!busy && <NanashiButton primary type="submit" disabled={disabled || noKeyringAvailable || !ready || !email.trim() || !password}>Se connecter à Apple</NanashiButton>}
      </form>}
    {challenge?.hasError && <p className="ni-notice" role="status">Apple demande une nouvelle validation. Vérifiez la méthode choisie et utilisez le dernier code reçu.</p>}
    {challenge?.unknown && <section className="ni-code-panel" aria-labelledby="verification-method"><h3 id="verification-method">Où recevoir le code Apple ?</h3><p>Choisissez une méthode proposée par votre compte.</p><div className="ni-methods"><button ref={deviceMethod} className="ni-button ni-primary" type="button" disabled={canceling || challengeSending} onClick={() => void requestCode("request-device-code")}>Sur mes appareils Apple</button>{challenge.numbers.filter(number => Number.isInteger(number.id) && typeof number.label === "string").map(number => <NanashiButton key={number.id} type="button" disabled={canceling || challengeSending} onClick={() => void requestCode("request-sms-code", number.id)}>Par SMS · ••••{number.label.replace(/\D/g, "").slice(-2)}</NanashiButton>)}</div></section>}
    {needsCode && <section className="ni-code-panel" aria-labelledby="verification-title"><h3 id="verification-title">{challenge?.sms ? "Le code reçu par SMS" : "Le code reçu sur votre appareil Apple"}</h3><p>Saisissez les six chiffres pour terminer la connexion.</p><form onSubmit={event => { event.preventDefault(); void sendCode(); }}><label htmlFor="apple-code">Code de validation<input ref={codeInput} id="apple-code" type="text" inputMode="numeric" autoComplete="one-time-code" pattern="[0-9]{6}" maxLength={6} value={code} onChange={event => setCode(event.target.value.replace(/\D/g, "").slice(0, 6))} disabled={canceling || challengeSending} /></label><NanashiButton primary type="submit" disabled={code.length !== 6 || canceling || challengeSending}>Valider le code</NanashiButton></form></section>}
    {busy && <div className="ni-auth-status"><p role="status">{canceling ? "Annulation en cours…" : needsCode ? "En attente du code Apple." : codeSent ? "Vérification du code…" : "Connexion à Apple en cours…"}</p><button className="ni-text-button" type="button" disabled={canceling} onClick={() => void cancelLogin()}>Annuler la connexion</button></div>}
    {error !== null && <NanashiError error={error} />}
  </div>;
};
