# Nanashi Installer

An independent, focused iPhone setup assistant based on [iloader 2.4.1](https://github.com/nab138/iloader/tree/v2.4.1). It prepares the official AltStore Classic 2.3.3 release, then hands off to the Nanashi website for the Apple confirmations and the Nanashi installation.

This is a preview implementation. Build and simulated UI checks do not establish successful Apple authentication, installation, migration, Health entitlements or background renewal on a physical iPhone. Do not describe the preview as an obstacle-free replacement until those checks have been performed.

## What it does

1. Requires an explicitly selected, paired iPhone running iOS 17.4 or later.
2. Signs in to Apple through the open-source iloader/isideload implementation, with native 2FA and cancellable, bounded requests.
3. Downloads a pinned official AltStore IPA over HTTPS, checking its exact size and SHA-256 before signing.
4. Embeds the supported installation metadata and places the pairing file in AltStore's documented local container.
5. Opens a first-party phone handoff: trust/developer mode if required, LocalDevVPN, Remote AltServer, Apple login, and the validated Nanashi installation link.

Nanashi itself is signed by AltStore, not by the bootstrap engine: the existing Health, App Groups, widget and keychain entitlements must not be silently simplified. The installer does not uninstall apps, randomize their identities, revoke certificates, reset Apple/Anisette state automatically, or copy health data. An existing app's data is not evidence of a successful migration; export a backup and retain the current copy until the new copy and permissions are checked.

## Requirements and limits

- Mac or Windows, iPhone iOS 17.4+, USB for initial preparation, an Apple account and its required 2FA.
- A functioning OS credential vault. There is no plaintext storage fallback; installer state is separate from iloader's existing vault.
- The free Apple signing period remains seven days. Remote AltServer requires a connected Wi-Fi network and LocalDevVPN. Native background refresh is scheduled by iOS, not guaranteed at 09:00.
- Apple can reject sign-in. AltStore 2.3.3 includes fixes for the reported -80045/-80046/415 series, but no installer can guarantee every account or device will authenticate.
- No new Developer ID or Windows signing certificate has been purchased. Unsigned preview packages may require an explicit OS opening confirmation. Global OS protection must not be disabled.
- Existing certificate limits stop the workflow; they never silently revoke a certificate used by other apps.

The SideStore shortcut shared for the Nanashi website targets a specific SideStore installation. It is not reused as if it could refresh AltStore.

## Build

Node 24, Rust stable, the platform's Tauri build prerequisites, and Xcode Command Line Tools on macOS are required.

```sh
npm ci --ignore-scripts
npm run build
cargo test --manifest-path src-tauri/Cargo.toml --lib
npm run tauri -- build
```

The app uses its own bundle ID, `com.rayanmakhlouf.nanashi.installer`. It does not use the upstream iloader update feed. Preview packages are built separately from the native Nanashi application. Do not commit signing material, pairing files, device logs or release binaries.

## Provenance

- iloader code: MIT; preserve [LICENSE](LICENSE) and [LICENSE-BRANDING](LICENSE-BRANDING). This is not an official iloader, SideStore or AltStore release. Upstream documentation is retained in [UPSTREAM_README.md](UPSTREAM_README.md).
- AltStore: downloaded unchanged from its official CDN and locally re-signed for the user's device. Its notices and license remain with that application. No third-party patched IPA is substituted.
- Interface: reuses Nanashi's static adaptations of [Glass Card by @educalvolpz](https://21st.dev/@educalvolpz/components/glass-card) and [Glass Button by @jahed](https://21st.dev/@jahed/components/glass-button). These are adaptations, not unchanged upstream components. The retrieved registry metadata did not supply individual license terms; no MIT claim is made for those visual sources.
- Nanashi icon and Harbor Blue tokens come from the existing Nanashi project. The native app remains an independent fork of [NOOP](https://github.com/ryanbr/noop), with its own license.

No analytics, advertising SDK, credential upload to a Nanashi server, or health-data collection is included. Apple services and the configured Anisette provider are network dependencies of signing. Credentials must never be included in logs, screenshots or support exports.
