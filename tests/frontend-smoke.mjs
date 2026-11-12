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
    let id = 0, account = null, resolveLogin, rejectLogin;
    const calls = [];
    const device = { id: 1, udid: "TEST-DEVICE-NOT-REAL", name: "iPhone de démo", version: scenario === "old-ios" ? "16.7.10" : "18.5", connectionType: "USB" };
    function notify(event, payload) {
      for (const [listenerId, listener] of listeners) if (listener.event === event) callbacks.get(listener.handler)?.({ event, id: listenerId, payload });
    }
    window.__nanashiMock = { calls, listeners, devices: scenario === "two-devices" ? [device, { ...device, id: 2, udid: "SECOND-TEST-DEVICE", name: "Autre iPhone" }] : [device] };
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
        if (command === "invalidate_account") { account = null; return null; }
        if (command === "plugin:event|listen") { const listenerId = ++id; listeners.set(listenerId, args); return listenerId; }
        if (command === "plugin:event|unlisten") { listeners.delete(args.eventId); return null; }
        if (command === "plugin:event|emit") {
          if (args.event === "2fa-recieved" && args.payload.action === "submit-code") { account = "preview@example.invalid"; resolveLogin?.(); }
          // A native follow-up can arrive before the emit acknowledgement resolves.
          else if (args.event === "2fa-recieved") notify("2fa-required", { requestId: "test-request-code", unknown: false, sms: args.payload.action === "request-sms-code", numbers: [], selectedNumberId: 42, hasError: false });
          return null;
        }
        if (command === "login_new") {
          if (scenario === "auth-error") throw { type: "auth", message: "-80045 FAKE_SECRET_DO_NOT_DISPLAY apple-network-body" };
          if (scenario === "certificate-limit") throw { type: "misc", message: "La limite de certificats Apple est atteinte. FAKE_SECRET_DO_NOT_DISPLAY" };
          if (scenario === "cancel-login") return new Promise((resolve, reject) => { resolveLogin = resolve; rejectLogin = reject; });
          return new Promise((resolve, reject) => { resolveLogin = resolve; rejectLogin = reject; setTimeout(() => notify("2fa-required", { requestId: scenario === "choose-method" ? "test-request-method" : "test-request-code", unknown: scenario === "choose-method", sms: false, numbers: scenario === "choose-method" ? [{ id: 42, label: "••••42" }] : [], selectedNumberId: null, hasError: false }), 0); });
        }
        if (command === "cancel_login") { setTimeout(() => rejectLogin?.({ type: "canceled", message: "canceled" }), 160); return null; }
        if (command === "plugin:opener|open_url") return null;
        if (command === "install_nanashi_manager_operation") {
          for (const stepId of ["preflight", "download", "prepare", "install", "pairing"]) {
            notify("operation_install_nanashi_manager", { updateType: "started", stepId });
            await new Promise(resolve => setTimeout(resolve, 70));
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
  expect(calls.find(call => call.command === "login_new").args).toMatchObject({ saveCredentials: false, anisetteServer: "https://mac-ani.jkcoxson.com" });
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
await run("post-install pairing failure remains incomplete", async () => {
  const { context, page } = await fixture("pairing-error"); await authenticate(page);
  await page.getByRole("button", { name: "Préparer mon iPhone" }).click();
  await expect(page.getByText("AltStore est installé, mais sa préparation reste incomplète.", { exact: true })).toBeVisible();
  await expect(page.getByRole("img", { name: /QR code/ })).toHaveCount(0);
  await expect(page.locator("body")).not.toContainText("FAKE_SECRET_DO_NOT_DISPLAY"); await context.close();
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
