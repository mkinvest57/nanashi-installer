// Browser-only IPC fixtures. This test never connects to Apple or a physical phone.
import { chromium, expect } from "@playwright/test";
import { mkdir, writeFile } from "node:fs/promises";

const baseURL = process.env.NANASHI_TEST_URL ?? "http://127.0.0.1:1420";
const output = new URL("../build/frontend/", import.meta.url);
await mkdir(output, { recursive: true });
const browser = await chromium.launch({ channel: process.env.PLAYWRIGHT_CHANNEL ?? "chrome", headless: true });
const results = [];

async function fixture(scenario = "success", viewport = { width: 980, height: 760 }) {
  const context = await browser.newContext({ viewport });
  await context.route(/^https:\/\//, route => route.abort());
  await context.addInitScript(({ scenario }) => {
    window.isTauri = true;
    const callbacks = new Map(), listeners = new Map();
    let id = 0, account = null, resolveLogin, rejectLogin, reuseRequested = false;
    const calls = [];
    const device = { id: 1, udid: "TEST-DEVICE-NOT-REAL", name: "iPhone de démo", version: scenario === "old-ios" ? "16.7.10" : "18.5", connectionType: "USB" };
    function notify(event, payload) {
      for (const [listenerId, listener] of listeners) if (listener.event === event) callbacks.get(listener.handler)?.({ event, id: listenerId, payload });
    }
    window.__nanashiMock = { calls, listeners, demo: device, devices: scenario === "hotplug" ? [] : scenario === "two-devices" ? [device, { ...device, id: 2, udid: "SECOND-TEST-DEVICE", name: "Autre iPhone" }] : [device] };
    window.__TAURI_EVENT_PLUGIN_INTERNALS__ = { unregisterListener: (_event, listenerId) => listeners.delete(listenerId) };
    window.__TAURI_INTERNALS__ = {
      transformCallback(callback) { const callbackId = ++id; callbacks.set(callbackId, callback); return callbackId; },
      unregisterCallback(callbackId) { callbacks.delete(callbackId); },
      async invoke(command, args) {
        calls.push({ command, args });
        if (command === "plugin:app|version") return "0.1.0";
        if (command === "keyring_available") return scenario !== "no-keyring";
        if (command === "nanashi_bootstrap_configuration") return { manager: "AltStore Classic", managerVersion: "2.3.3", minimumIos: "17.4" };
        if (command === "list_devices") return window.__nanashiMock.devices.map(device => ({ Ok: device }));
        if (command === "set_selected_device" || command === "cancel_pairing") return null;
        if (command === "logged_in_as") return account;
        if (command === "signing_status") {
          if (scenario === "reuse-status-error") throw { type: "existing_signature", message: "Code : EXISTING-UNVERIFIED. FAKE_SECRET_DO_NOT_DISPLAY" };
          return { mode: reuseRequested && scenario !== "reuse-mode-mismatch" ? "existing" : "standard", verified: reuseRequested && scenario !== "reuse-unverified" };
        }
        if (command === "invalidate_account") { account = null; return null; }
        if (command === "plugin:event|listen") {
          if (args.event === "2fa-required" && scenario === "listener-error" && !window.__nanashiMock.listenerReady) throw "FAKE_SECRET_DO_NOT_DISPLAY";
          const listenerId = ++id; listeners.set(listenerId, args); return listenerId;
        }
        if (command === "plugin:event|unlisten") { listeners.delete(args.eventId); return null; }
        if (command === "plugin:event|emit") {
          if (args.event === "2fa-recieved" && scenario === "delivery-error" && !window.__nanashiMock.deliveryReady) throw "FAKE_SECRET_DO_NOT_DISPLAY";
          if (args.event === "2fa-recieved" && args.payload.action === "submit-code") { account = "preview@example.invalid"; resolveLogin?.(); }
          // A native follow-up can arrive before the emit acknowledgement resolves.
          else if (args.event === "2fa-recieved") notify("2fa-required", { requestId: "test-request-code", unknown: false, sms: args.payload.action === "request-sms-code", numbers: [], selectedNumberId: 42, hasError: false });
          return null;
        }
        if (command === "login_new") {
          reuseRequested = args.reuseExistingSignature === true;
          if (scenario === "expire-challenge") window.__nanashiMock.expireChallenge = () => rejectLogin({ type: "auth", message: "Code : AUTH-2FA-TIMEOUT." });
          const reuseErrorMarkers = { "reuse-missing-key": "EXISTING-KEY-MISSING", "reuse-certificate-mismatch": "EXISTING-CERTIFICATE-MISMATCH", "reuse-network": "EXISTING-NETWORK", "reuse-guard": "EXISTING-GUARD", "reuse-unknown-error": "EXISTING-KEY-MISSING-UNTRUSTED" };
          if (reuseErrorMarkers[scenario]) throw { type: "existing_signature", message: `Code : ${reuseErrorMarkers[scenario]}. FAKE_SECRET_DO_NOT_DISPLAY` };
          if (scenario === "auth-error") throw { type: "auth", message: "Apple a refusé la demande (-80045). FAKE_SECRET_DO_NOT_DISPLAY" };
          if (scenario.startsWith("AUTH-")) throw { type: scenario === "AUTH-PROVIDER" ? "anisette" : "auth", message: `${scenario === "AUTH-SERVICE" ? "Le service de connexion a renvoyé une erreur HTTP 503. " : ""}Code : ${scenario}. FAKE_SECRET_DO_NOT_DISPLAY -80045` };
          if (scenario === "certificate-limit") throw { type: "developer", message: "La limite de certificats Apple est atteinte. FAKE_SECRET_DO_NOT_DISPLAY" };
          if (scenario === "cancel-login") return new Promise((resolve, reject) => { resolveLogin = resolve; rejectLogin = reject; });
          return new Promise((resolve, reject) => { resolveLogin = resolve; rejectLogin = reject; setTimeout(() => notify("2fa-required", { requestId: scenario === "choose-method" ? "test-request-method" : "test-request-code", unknown: scenario === "choose-method", sms: false, numbers: scenario === "choose-method" ? [{ id: 42, label: "••••42" }] : [], selectedNumberId: null, hasError: false }), 0); });
        }
        if (command === "cancel_login") { setTimeout(() => rejectLogin?.({ type: "canceled", message: "canceled" }), 160); return null; }
        if (command === "plugin:opener|open_url") return null;
        if (command === "install_nanashi_manager_operation") {
          for (const stepId of ["preflight", "download", "prepare", "install", "pairing"]) {
            notify("operation_install_nanashi_manager", { updateType: "started", stepId });
            await new Promise(resolve => setTimeout(resolve, 70));
            const preparationErrors = {
              "installation-quota": { type: "max_apps", message: "La limite d’apps de développement est atteinte. FAKE_SECRET_DO_NOT_DISPLAY" },
              "installation-signature": { type: "installation_failed", message: "La signature d’AltStore a échoué. Code : INSTALL-SIGNATURE. FAKE_SECRET_DO_NOT_DISPLAY -80045" },
              "installation-developer": { type: "developer", message: "Le service développeur Apple a refusé la signature (9412). FAKE_SECRET_DO_NOT_DISPLAY" },
              "installation-unknown-marker": { type: "installation_failed", message: "Code : INSTALL-SIGNATURE-UNTRUSTED. FAKE_SECRET_DO_NOT_DISPLAY -80045" },
            };
            if (stepId === "prepare" && preparationErrors[scenario]) {
              const error = preparationErrors[scenario];
              notify("operation_install_nanashi_manager", { updateType: "failed", stepId, extraDetails: error });
              throw error;
            }
            if (scenario === "installation-uncertain" && stepId === "install") {
              const error = { type: "installation_uncertain", message: "Native installation timed out; device state unknown" };
              notify("operation_install_nanashi_manager", { updateType: "failed", stepId, extraDetails: error });
              throw error;
            }
            if (scenario === "pairing-error" && stepId === "pairing") {
              const error = { type: "remote_pairing", message: "FAKE_SECRET_DO_NOT_DISPLAY" };
              notify("operation_install_nanashi_manager", { updateType: "failed", stepId, extraDetails: error });
              throw error;
            }
            notify("operation_install_nanashi_manager", { updateType: "finished", stepId });
          }
          return { manager: "AltStore Classic", managerVersion: "2.3.3", managerBundleIdentifier: "example.test.altstore", deviceName: device.name, pairingPlaced: scenario !== "invalid-result", nanashiInstalled: false, nextStep: "finish_on_iphone", nanashiInstallUrl: "altstore-classic://install?url=https%3A%2F%2Fexample.invalid%2Ftest.ipa" };
        }
        throw new Error(`Unexpected mocked command: ${command}`);
      },
    };
  }, { scenario });
  const page = await context.newPage();
  const errors = [];
  page.on("pageerror", error => errors.push(error.message));
  await page.goto(baseURL);
  await expect(page.getByRole("heading", { level: 2, name: "Votre iPhone", exact: true })).toBeVisible();
  return { context, page, errors };
}

async function selectPhone(page) {
  await page.getByRole("button", { name: /iPhone de démo/ }).click();
  await page.getByRole("button", { name: "Continuer", exact: true }).click();
  await expect(page.getByRole("heading", { level: 2, name: "Compte Apple", exact: true })).toBeVisible();
}
async function submitLogin(page) {
  await page.getByRole("textbox", { name: "Compte Apple", exact: true }).fill("preview@example.invalid");
  await page.getByLabel("Mot de passe", { exact: true }).fill("fixture-not-a-real-password");
  await page.getByRole("button", { name: "Se connecter à Apple", exact: true }).click();
}
async function authenticate(page) {
  await selectPhone(page); await submitLogin(page);
  await expect(page.getByLabel("Code de validation", { exact: true })).toBeFocused();
  await page.getByLabel("Code de validation", { exact: true }).fill("123456");
  await page.getByRole("button", { name: "Valider le code", exact: true }).click();
  await expect(page.getByText("Compte Apple connecté", { exact: true })).toBeVisible();
  await page.getByRole("button", { name: "Continuer", exact: true }).click();
}
async function run(name, action) {
  try { await action(); results.push({ name, passed: true }); console.log(`PASS ${name}`); }
  catch (error) { results.push({ name, passed: false, error: String(error) }); console.error(`FAIL ${name}: ${error}`); }
}

await run("ordinary browser cannot collect Apple credentials", async () => {
  const page = await browser.newPage(); await page.goto(baseURL);
  await expect(page.getByRole("heading", { name: "Ouvrez l’application Nanashi Installer" })).toBeVisible();
  await expect(page.locator("input")).toHaveCount(0); await page.close();
});
await run("explicit device selection, 2FA and verified manager-only completion", async () => {
  const { context, page, errors } = await fixture();
  await expect(page.getByRole("button", { name: "Continuer", exact: true })).toBeDisabled();
  expect(await page.evaluate(() => window.__nanashiMock.calls.filter(call => call.command === "set_selected_device").length)).toBe(0);
  await page.screenshot({ path: new URL("01-device.png", output).pathname, fullPage: true });
  await selectPhone(page); await page.screenshot({ path: new URL("02-account.png", output).pathname, fullPage: true });
  await submitLogin(page); await expect(page.getByLabel("Code de validation")).toBeFocused();
  await expect(page.getByLabel("Mot de passe", { exact: true })).toHaveValue("");
  await page.getByLabel("Code de validation").fill("123456"); await page.getByRole("button", { name: "Valider le code" }).click();
  await expect(page.getByText("Compte Apple connecté", { exact: true })).toBeVisible();
  await page.getByRole("button", { name: "Continuer", exact: true }).click();
  await page.getByRole("button", { name: "Préparer mon iPhone", exact: true }).click();
  await expect(page.getByRole("navigation").getByRole("button").first()).toBeDisabled();
  await page.screenshot({ path: new URL("03-progress.png", output).pathname, fullPage: true });
  await expect(page.getByText("AltStore est prêt sur iPhone de démo.", { exact: true })).toBeVisible();
  await expect(page.getByRole("img", { name: /QR code pour terminer/ })).toHaveAttribute("src", "/nanashi-iphone-qr.svg");
  await expect(page.locator("a.ni-readable-link")).toHaveAttribute("href", "https://nanashi-mk.vercel.app/installation-nanashi?step=iphone#installation-etape");
  await expect(page.getByText(/Nanashi est installée/, { exact: false })).toHaveCount(0);
  const calls = await page.evaluate(() => window.__nanashiMock.calls);
  expect(calls.filter(call => call.command === "login_new")).toHaveLength(1);
  expect(calls.find(call => call.command === "login_new").args).toMatchObject({ saveCredentials: false, anisetteServer: "https://mac-ani.jkcoxson.com", reuseExistingSignature: false });
  expect(calls.filter(call => call.command === "install_nanashi_manager_operation")).toHaveLength(1);
  expect(calls.some(call => /revoke|delete_account|install_sidestore|sideload|check.*update/.test(call.command))).toBe(false);
  expect(await page.evaluate(() => [...window.__nanashiMock.listeners.values()].filter(listener => listener.event === "operation_install_nanashi_manager").length)).toBe(0);
  await page.screenshot({ path: new URL("04-handoff.png", output).pathname, fullPage: true });
  expect(errors).toEqual([]); await context.close();
});
await run("Apple -80045 is visible without raw response or automatic retries", async () => {
  const { context, page, errors } = await fixture("auth-error"); await selectPhone(page); await submitLogin(page);
  await expect(page.getByRole("alert")).toContainText("-80045");
  await expect(page.locator("body")).not.toContainText("FAKE_SECRET_DO_NOT_DISPLAY");
  await expect(page.getByLabel("Mot de passe", { exact: true })).toHaveValue("");
  expect(await page.evaluate(() => window.__nanashiMock.calls.filter(call => call.command === "login_new").length)).toBe(1);
  expect(errors).toEqual([]); await context.close();
});
for (const [scenario, title] of [
  ["AUTH-DISCOVERY", "Les services Apple n’ont pas pu être préparés"],
  ["AUTH-SIGN-IN", "La connexion au compte Apple n’a pas abouti"],
  ["AUTH-2FA", "La validation en deux étapes n’a pas abouti"],
  ["AUTH-DEVELOPER-SESSION", "La session de signature Apple n’a pas pu être ouverte"],
  ["AUTH-NETWORK", "La connexion réseau a été interrompue"],
  ["AUTH-SERVICE", "Le service de connexion est temporairement indisponible"],
  ["AUTH-RATE-LIMIT", "Le service demande d’espacer les tentatives"],
  ["AUTH-TIMEOUT", "Le délai de connexion est dépassé"],
  ["AUTH-2FA-TIMEOUT", "Le délai de validation du code est dépassé"],
  ["AUTH-PROVIDER", "Le service de préparation de la connexion est indisponible"],
  ["AUTH-2FA-UNRECOGNIZED", "La connexion Apple n’a pas abouti"],
]) await run(`${scenario} gives only the matching recovery action and keeps the submitted account`, async () => {
  const { context, page, errors } = await fixture(scenario); await selectPhone(page);
  const reuse = page.getByRole("checkbox", { name: "Réutiliser ma signature iloader existante" });
  await reuse.check(); await submitLogin(page);
  const alert = page.getByRole("alert");
  await expect(alert).toContainText(title);
  if (!scenario.endsWith("UNRECOGNIZED")) await expect(alert).toContainText(`(${scenario})`);
  if (scenario === "AUTH-SERVICE") await expect(alert).toContainText("HTTP 503");
  await expect(alert).not.toContainText(/-80045|UNRECOGNIZED|FAKE_SECRET_DO_NOT_DISPLAY|Vérifiez vos identifiants/);
  await expect(page.getByRole("textbox", { name: "Compte Apple", exact: true })).toHaveValue("preview@example.invalid");
  await expect(reuse).toBeChecked();
  const password = page.getByLabel("Mot de passe", { exact: true });
  await expect(password).toHaveValue("");
  await expect(password).toHaveAccessibleDescription(/champ du mot de passe a été vidé/);
  expect(await page.evaluate(() => window.__nanashiMock.calls.filter(call => call.command === "login_new").map(call => call.args.password))).toEqual(["fixture-not-a-real-password"]);
  await expect(page.getByRole("button", { name: "Continuer", exact: true })).toBeDisabled();
  expect(errors).toEqual([]); await context.close();
});
await run("login waits for a verification listener and resumes only on manual submit", async () => {
  const { context, page, errors } = await fixture("listener-error"); await selectPhone(page);
  const login = page.getByRole("button", { name: "Se connecter à Apple" });
  await page.getByRole("textbox", { name: "Compte Apple", exact: true }).fill("preview@example.invalid");
  await page.getByLabel("Mot de passe", { exact: true }).fill("fixture-not-a-real-password");
  await expect(login).toBeDisabled();
  await expect(page.getByRole("alert")).toContainText("ne peut pas recevoir la validation Apple");
  await expect(page.locator("body")).not.toContainText("FAKE_SECRET_DO_NOT_DISPLAY");
  await page.evaluate(() => { window.__nanashiMock.listenerReady = true; });
  await page.getByRole("button", { name: "Réactiver la validation" }).click();
  await expect(login).toBeEnabled();
  expect(await page.evaluate(() => window.__nanashiMock.calls.filter(call => call.command === "login_new"))).toHaveLength(0);
  await login.click(); await expect(page.getByLabel("Code de validation")).toBeFocused();
  expect(errors).toEqual([]); await context.close();
});
await run("a failed code submission keeps the current challenge available for a manual retry", async () => {
  const { context, page, errors } = await fixture("delivery-error"); await selectPhone(page); await submitLogin(page);
  const code = page.getByLabel("Code de validation"), submit = page.getByRole("button", { name: "Valider le code" });
  await code.fill("123456"); await submit.click();
  await expect(page.getByRole("alert")).toContainText("La réponse de validation n’a pas été transmise");
  await expect(code).toHaveValue(""); await expect(code).toBeEnabled();
  await expect(page.locator("body")).not.toContainText("FAKE_SECRET_DO_NOT_DISPLAY");
  await page.evaluate(() => { window.__nanashiMock.deliveryReady = true; });
  await code.fill("123456"); await submit.click();
  await expect(page.getByText("Compte Apple connecté", { exact: true })).toBeVisible();
  expect(await page.evaluate(() => window.__nanashiMock.calls.filter(call => call.command === "login_new"))).toHaveLength(1);
  expect(errors).toEqual([]); await context.close();
});
await run("a verification timeout dismisses the expired prompt and preserves the selected signing mode", async () => {
  const { context, page, errors } = await fixture("expire-challenge"); await selectPhone(page);
  const reuse = page.getByRole("checkbox", { name: "Réutiliser ma signature iloader existante" });
  await reuse.check(); await submitLogin(page);
  await expect(page.getByLabel("Code de validation")).toBeFocused();
  await page.evaluate(() => window.__nanashiMock.expireChallenge());
  await expect(page.getByRole("alert")).toContainText("AUTH-2FA-TIMEOUT");
  await expect(page.getByLabel("Code de validation")).toHaveCount(0);
  await expect(page.getByRole("button", { name: "Se connecter à Apple" })).toBeDisabled();
  await expect(reuse).toBeChecked();
  expect(await page.evaluate(() => window.__nanashiMock.calls.filter(call => call.command === "login_new"))).toHaveLength(1);
  expect(errors).toEqual([]); await context.close();
});
await run("a phone plugged in after launch appears automatically without starting pairing", async () => {
  const { context, page, errors } = await fixture("hotplug");
  const next = page.getByRole("button", { name: "Continuer", exact: true });
  await expect(next).toBeDisabled();
  await expect(page.getByText("Branchez votre iPhone", { exact: true })).toBeVisible();
  await page.evaluate(() => { window.__nanashiMock.devices.push(window.__nanashiMock.demo); });
  const phone = page.getByRole("button", { name: /iPhone de démo/ });
  await expect(phone).toBeVisible({ timeout: 8500 });
  expect(await page.evaluate(() => window.__nanashiMock.calls.filter(c => c.command === "set_selected_device").length)).toBe(0);
  await phone.click();
  await expect(next).toBeEnabled();
  await page.evaluate(() => { window.__nanashiMock.devices = []; });
  await expect(next).toBeDisabled({ timeout: 8500 });
  expect(errors).toEqual([]); await context.close();
});
await run("real udid identity distinguishes phones and invalidates stale preparation", async () => {
  const { context, page, errors } = await fixture("two-devices");
  await page.getByRole("button", { name: /iPhone de démo/ }).click();
  await expect(page.getByRole("button", { name: /iPhone de démo/ })).toHaveAttribute("aria-pressed", "true");
  await expect(page.getByRole("button", { name: /Autre iPhone/ })).toHaveAttribute("aria-pressed", "false");
  await authenticate(page);
  await page.getByRole("button", { name: "Préparer mon iPhone", exact: true }).click();
  await expect(page.getByText("AltStore est prêt sur iPhone de démo.", { exact: true })).toBeVisible();
  await page.getByRole("navigation").getByRole("button").first().click();
  await page.getByRole("button", { name: /Autre iPhone/ }).click();
  await expect(page.getByRole("button", { name: /iPhone de démo/ })).toHaveAttribute("aria-pressed", "false");
  await expect(page.getByRole("button", { name: /Autre iPhone/ })).toHaveAttribute("aria-pressed", "true");
  await expect(page.getByRole("navigation").getByRole("button").last()).toBeDisabled();
  const selection = await page.evaluate(() => window.__nanashiMock.calls.filter(call => call.command === "set_selected_device").at(-1));
  expect(selection.args.device.udid).toBe("SECOND-TEST-DEVICE");
  await page.evaluate(() => { window.__nanashiMock.devices = []; });
  await page.getByRole("button", { name: "Rechercher à nouveau", exact: true }).click();
  await expect(page.getByRole("button", { name: "Continuer", exact: true })).toBeDisabled();
  expect(errors).toEqual([]); await context.close();
});
await run("Apple delivery choice uses masked numbers and challenge-bound responses", async () => {
  const { context, page, errors } = await fixture("choose-method"); await selectPhone(page); await submitLogin(page);
  await expect(page.getByRole("heading", { name: "Où recevoir le code Apple ?" })).toBeVisible();
  await expect(page.getByLabel("Code de validation")).toHaveCount(0);
  await page.getByRole("button", { name: "Par SMS · ••••42", exact: true }).click();
  await expect(page.getByRole("heading", { name: "Le code reçu par SMS" })).toBeVisible();
  await page.getByLabel("Code de validation").fill("123456"); await page.getByRole("button", { name: "Valider le code" }).click();
  await expect(page.getByText("Compte Apple connecté", { exact: true })).toBeVisible();
  const responses = await page.evaluate(() => window.__nanashiMock.calls.filter(call => call.command === "plugin:event|emit").map(call => call.args.payload));
  expect(responses).toEqual([{ requestId: "test-request-method", action: "request-sms-code", phoneId: 42 }, { requestId: "test-request-code", action: "submit-code", code: "123456" }]);
  expect(errors).toEqual([]); await context.close();
});
await run("unavailable keyring blocks login", async () => {
  const { context, page } = await fixture("no-keyring"); await selectPhone(page);
  await expect(page.getByRole("alert")).toContainText("Déverrouillez le trousseau");
  await expect(page.getByRole("button", { name: "Se connecter à Apple" })).toBeDisabled();
  expect(await page.evaluate(() => window.__nanashiMock.calls.some(call => call.command === "login_new"))).toBe(false); await context.close();
});
await run("pending Apple login can be canceled without automatic restart", async () => {
  const { context, page, errors } = await fixture("cancel-login"); await selectPhone(page); await submitLogin(page);
  await page.getByRole("button", { name: "Annuler la connexion" }).click();
  await expect(page.getByRole("button", { name: "Annuler la connexion" })).toBeDisabled();
  await expect(page.getByLabel("Mot de passe", { exact: true })).toBeDisabled();
  await expect(page.getByLabel("Mot de passe", { exact: true })).toBeEnabled();
  expect(await page.evaluate(() => window.__nanashiMock.calls.filter(call => call.command === "cancel_login").length)).toBe(1);
  expect(await page.evaluate(() => window.__nanashiMock.calls.filter(call => call.command === "login_new").length)).toBe(1);
  expect(errors).toEqual([]); await context.close();
});
await run("certificate exhaustion is explained without exposing a revocation control", async () => {
  const { context, page } = await fixture("certificate-limit"); await selectPhone(page); await submitLogin(page);
  await expect(page.getByRole("alert")).toContainText("Limite de certificats Apple atteinte");
  await expect(page.getByRole("alert")).toContainText("Aucun certificat ni profil existant n’a été révoqué");
  await expect(page.locator("body")).not.toContainText("FAKE_SECRET_DO_NOT_DISPLAY");
  expect(await page.evaluate(() => window.__nanashiMock.calls.some(call => /revoke|delete_certificate/.test(call.command)))).toBe(false);
  await context.close();
});
await run("existing signature reuse requires explicit opt-in and verified native status", async () => {
  const { context, page, errors } = await fixture(); await selectPhone(page);
  const reuse = page.getByRole("checkbox", { name: "Réutiliser ma signature iloader existante", exact: true });
  await expect(reuse).not.toBeChecked();
  await expect(page.getByText("Signature existante vérifiée", { exact: true })).toHaveCount(0);
  await reuse.check(); await submitLogin(page);
  await expect(reuse).toBeDisabled();
  await expect(page.getByText("Signature existante vérifiée", { exact: true })).toHaveCount(0);
  await page.getByLabel("Code de validation").fill("123456"); await page.getByRole("button", { name: "Valider le code" }).click();
  await expect(page.getByText("Signature existante vérifiée", { exact: true })).toBeVisible();
  await expect(page.getByRole("button", { name: "Continuer", exact: true })).toBeEnabled();
  await page.getByRole("button", { name: "Continuer", exact: true }).click();
  await page.getByRole("button", { name: "Retour", exact: true }).click();
  await expect(page.getByText("Signature existante vérifiée", { exact: true })).toBeVisible();
  const calls = await page.evaluate(() => window.__nanashiMock.calls);
  expect(calls.find(call => call.command === "login_new").args).toMatchObject({ reuseExistingSignature: true, saveCredentials: false });
  expect(calls.filter(call => call.command === "signing_status").length).toBeGreaterThanOrEqual(2);
  expect(calls.some(call => /revoke|delete_certificate|install_nanashi_manager_operation/.test(call.command))).toBe(false);
  await page.screenshot({ path: new URL("06-existing-signature.png", output).pathname, fullPage: true });
  await page.getByRole("button", { name: "Modifier la connexion", exact: true }).click();
  await expect(page.getByText("Signature existante vérifiée", { exact: true })).toHaveCount(0);
  await expect(page.getByRole("button", { name: "Continuer", exact: true })).toBeDisabled();
  expect(errors).toEqual([]); await context.close();
});
for (const scenario of ["reuse-unverified", "reuse-mode-mismatch", "reuse-status-error"]) await run(`${scenario} cannot proceed as a verified existing signature`, async () => {
  const { context, page, errors } = await fixture(scenario); await selectPhone(page);
  await page.getByRole("checkbox", { name: "Réutiliser ma signature iloader existante", exact: true }).check();
  await submitLogin(page);
  await page.getByLabel("Code de validation").fill("123456"); await page.getByRole("button", { name: "Valider le code" }).click();
  await expect(page.getByRole("alert")).toContainText("La réutilisation de la signature n’est pas confirmée");
  await expect(page.getByText("Signature existante vérifiée", { exact: true })).toHaveCount(0);
  await expect(page.getByText("Compte Apple connecté", { exact: true })).toHaveCount(0);
  await expect(page.getByRole("button", { name: "Continuer", exact: true })).toBeDisabled();
  await expect(page.locator("body")).not.toContainText("FAKE_SECRET_DO_NOT_DISPLAY");
  expect(await page.evaluate(() => window.__nanashiMock.calls.some(call => call.command === "install_nanashi_manager_operation"))).toBe(false);
  expect(errors).toEqual([]); await context.close();
});
for (const [scenario, diagnostic] of [
  ["reuse-missing-key", "La clé de signature iloader est introuvable"],
  ["reuse-certificate-mismatch", "Aucun certificat ne correspond à cette clé"],
  ["reuse-network", "La signature existante n’a pas pu être vérifiée"],
  ["reuse-guard", "Une modification de certificat a été bloquée"],
  ["reuse-unknown-error", "La signature existante n’a pas pu être réutilisée"],
]) await run(`${scenario} explains recovery without raw native error content`, async () => {
  const { context, page, errors } = await fixture(scenario); await selectPhone(page);
  await page.getByRole("checkbox", { name: "Réutiliser ma signature iloader existante", exact: true }).check();
  await submitLogin(page);
  await expect(page.getByRole("alert")).toContainText(diagnostic);
  await expect(page.locator("body")).not.toContainText("FAKE_SECRET_DO_NOT_DISPLAY");
  await expect(page.getByRole("button", { name: "Continuer", exact: true })).toBeDisabled();
  await expect(page.getByRole("checkbox", { name: "Réutiliser ma signature iloader existante", exact: true })).toBeChecked();
  expect(await page.evaluate(() => window.__nanashiMock.calls.filter(call => call.command === "login_new").length)).toBe(1);
  expect(await page.evaluate(() => window.__nanashiMock.calls.some(call => /revoke|delete_certificate|install_nanashi_manager_operation/.test(call.command)))).toBe(false);
  expect(errors).toEqual([]); await context.close();
});
await run("post-install pairing failure remains incomplete", async () => {
  const { context, page } = await fixture("pairing-error"); await authenticate(page);
  await page.getByRole("button", { name: "Préparer mon iPhone" }).click();
  await expect(page.getByText("AltStore est installé, mais sa préparation reste incomplète.", { exact: true })).toBeVisible();
  await expect(page.getByRole("img", { name: /QR code/ })).toHaveCount(0);
  await expect(page.locator("body")).not.toContainText("FAKE_SECRET_DO_NOT_DISPLAY"); await context.close();
});
for (const [scenario, diagnostic] of [
  ["installation-quota", "La limite d’apps de développement est atteinte"],
  ["installation-signature", "La signature d’AltStore a échoué (INSTALL-SIGNATURE)"],
  ["installation-developer", "La signature Apple demande une vérification (9412)"],
  ["installation-unknown-marker", "L’installation d’AltStore a échoué"],
]) await run(`${scenario} remains an installation diagnostic without private report content`, async () => {
  const { context, page, errors } = await fixture(scenario); await authenticate(page);
  await page.getByRole("button", { name: "Préparer mon iPhone" }).click();
  await expect(page.getByRole("alert")).toContainText(diagnostic);
  await expect(page.getByRole("alert")).not.toContainText(/mot de passe|identifiants|connexion Apple|refusé la connexion|-80045|FAKE_SECRET_DO_NOT_DISPLAY/);
  await expect(page.getByRole("img", { name: /QR code/ })).toHaveCount(0);
  await expect(page.locator("body")).not.toContainText("FAKE_SECRET_DO_NOT_DISPLAY");
  if (scenario === "installation-signature") await expect(page.getByRole("alert")).toContainText("avant le transfert sur l’iPhone");
  if (scenario === "installation-unknown-marker") await expect(page.getByRole("alert")).not.toContainText("INSTALL-SIGNATURE");
  const calls = await page.evaluate(() => window.__nanashiMock.calls);
  expect(calls.filter(call => call.command === "install_nanashi_manager_operation")).toHaveLength(1);
  expect(calls.filter(call => call.command === "login_new")).toHaveLength(1);
  expect(calls.some(call => /revoke|delete_certificate/.test(call.command))).toBe(false);
  expect(errors).toEqual([]); await context.close();
});
await run("uncertain installation requires a phone check before any manual retry", async () => {
  const { context, page } = await fixture("installation-uncertain"); await authenticate(page);
  await page.getByRole("button", { name: "Préparer mon iPhone" }).click();
  await expect(page.getByRole("alert")).toContainText("Le résultat de l’installation n’a pas pu être confirmé ; l’iPhone peut encore terminer");
  await expect(page.getByRole("button", { name: "Réessayer la préparation", exact: true })).toBeDisabled();
  await expect(page.getByRole("img", { name: /QR code/ })).toHaveCount(0);
  await page.getByRole("button", { name: "J’ai vérifié l’état sur l’iPhone", exact: true }).click();
  await expect(page.getByRole("button", { name: "Réessayer la préparation", exact: true })).toBeEnabled();
  expect(await page.evaluate(() => window.__nanashiMock.calls.filter(call => call.command === "install_nanashi_manager_operation").length)).toBe(1);
  await context.close();
});
await run("unsupported iOS cannot start setup", async () => {
  const { context, page } = await fixture("old-ios");
  await expect(page.getByRole("button", { name: /iPhone de démo/ })).toBeDisabled();
  await expect(page.getByRole("button", { name: "Continuer", exact: true })).toBeDisabled();
  await expect(page.getByText("Cette préparation nécessite iOS 17.4 ou plus récent.")).toBeVisible(); await context.close();
});
await run("unverified result cannot claim completed preparation", async () => {
  const { context, page } = await fixture("invalid-result"); await authenticate(page);
  await page.getByRole("button", { name: "Préparer mon iPhone" }).click();
  await expect(page.getByRole("alert")).toBeVisible();
  await expect(page.getByRole("img", { name: /QR code/ })).toHaveCount(0); await context.close();
});
await run("small window and large text remain usable", async () => {
  const { context, page } = await fixture("success", { width: 640, height: 560 });
  await page.emulateMedia({ reducedMotion: "reduce" });
  await page.evaluate(() => { document.documentElement.style.fontSize = "150%"; });
  await authenticate(page);
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
  const bounds = await page.getByRole("button", { name: "Préparer mon iPhone" }).boundingBox();
  expect(bounds.height).toBeGreaterThanOrEqual(44);
  await page.screenshot({ path: new URL("05-small-large-text.png", output).pathname, fullPage: true }); await context.close();
});

await browser.close();
await writeFile(new URL("results.json", output), JSON.stringify(results, null, 2));
if (results.some(result => !result.passed)) process.exitCode = 1;
