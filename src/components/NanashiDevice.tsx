import { useEffect, useRef, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { FiCheck, FiRefreshCw, FiSmartphone } from "react-icons/fi";
import type { DeviceInfo } from "../Device";
import { NanashiButton, NanashiError } from "./NanashiGlass";

export function isSupportedIOS(version: string, minimum: string): boolean {
  if (!/^\d+(?:\.\d+)*$/.test(version) || !/^\d+(?:\.\d+)*$/.test(minimum)) return false;
  const actual = version.split(".").map(Number), required = minimum.split(".").map(Number);
  for (let index = 0; index < Math.max(actual.length, required.length); index += 1) {
    if ((actual[index] ?? 0) !== (required[index] ?? 0)) return (actual[index] ?? 0) > (required[index] ?? 0);
  }
  return true;
}

export function NanashiDevice({ selectedDevice, onSelect, onBusyChange, minimumIos }: {
  selectedDevice: DeviceInfo | null; onSelect: (device: DeviceInfo | null) => void; onBusyChange: (busy: boolean) => void; minimumIos?: string;
}) {
  const [devices, setDevices] = useState<DeviceInfo[]>([]);
  const [loading, setLoading] = useState(false);
  const [pairing, setPairing] = useState<DeviceInfo | null>(null);
  const [error, setError] = useState<unknown>(null);
  const generation = useRef(0);
  const mounted = useRef(true);

  async function refresh() {
    const request = ++generation.current;
    setLoading(true); setError(null); onBusyChange(true);
    try {
      const results = await invoke<Array<{ Ok: DeviceInfo } | { Err: unknown }>>("list_devices");
      if (!mounted.current || request !== generation.current) return;
      const found = results.flatMap(result => "Ok" in result ? [result.Ok] : []);
      setDevices(found);
      if (!found.length) {
        const failed = results.find(result => "Err" in result);
        if (failed && "Err" in failed) setError(failed.Err);
      }
      if (selectedDevice && !found.some(device => device.udid === selectedDevice.udid)) onSelect(null);
    } catch (failure) {
      if (mounted.current && request === generation.current) { setError(failure); setDevices([]); onSelect(null); }
    } finally {
      if (mounted.current && request === generation.current) { setLoading(false); onBusyChange(false); }
    }
  }
  async function select(device: DeviceInfo) {
    const request = ++generation.current;
    setPairing(device); setError(null); onBusyChange(true); onSelect(null);
    try {
      await invoke("set_selected_device", { device });
      if (mounted.current && request === generation.current) onSelect(device);
    } catch (failure) { if (mounted.current && request === generation.current) setError(failure); }
    finally { if (mounted.current && request === generation.current) { setPairing(null); onBusyChange(false); } }
  }
  async function cancelPairing() {
    try { await invoke("cancel_pairing"); generation.current += 1; setPairing(null); onSelect(null); onBusyChange(false); }
    catch (failure) { setError(failure); }
  }
  useEffect(() => {
    mounted.current = true; void refresh();
    return () => { mounted.current = false; generation.current += 1; onBusyChange(false); };
  }, []);
  return <div className="ni-device-list">
    {loading && <p role="status">Recherche des iPhone branchés…</p>}
    {!loading && !devices.length && !error && <div className="ni-empty"><FiSmartphone aria-hidden="true" /><strong>Branchez votre iPhone</strong><p>Déverrouillez-le, puis acceptez « Faire confiance à cet ordinateur » si la demande apparaît.</p></div>}
    {devices.map(device => <button type="button" key={device.udid} className="ni-device" disabled={loading || pairing !== null || (minimumIos !== undefined && !isSupportedIOS(device.version, minimumIos))} aria-pressed={selectedDevice?.udid === device.udid} onClick={() => void select(device)}>
      <FiSmartphone aria-hidden="true" /><span><strong>{device.name}</strong><small>{device.connectionType === "USB" ? "Branché par USB" : device.connectionType === "Network" ? "Connexion réseau" : "Connexion détectée"} · iOS {device.version}</small>{minimumIos && !isSupportedIOS(device.version, minimumIos) && <small>Cette préparation nécessite iOS {minimumIos} ou plus récent.</small>}</span>
      {selectedDevice?.udid === device.udid && <FiCheck aria-label="Sélectionné" />}
    </button>)}
    {pairing && <div className="ni-notice" role="status"><strong>Confirmez sur {pairing.name}</strong><p>Gardez l’iPhone déverrouillé et acceptez la demande de confiance si elle apparaît.</p><button className="ni-text-button" type="button" onClick={() => void cancelPairing()}>Annuler la sélection</button></div>}
    {error !== null && <NanashiError error={error} />}
    <NanashiButton type="button" disabled={loading || pairing !== null} onClick={() => void refresh()}><FiRefreshCw aria-hidden="true" />Rechercher à nouveau</NanashiButton>
  </div>;
}
