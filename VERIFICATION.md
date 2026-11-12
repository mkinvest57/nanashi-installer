# Preview verification

Local checks on 2026-11-12:

- Rust unit tests: 26 passed, no network, credentials or device access.
- Frontend production build passed, 78.45 KB gzip JavaScript.
- Browser IPC scenarios: 12 passed, using synthetic native responses only.
- Official AltStore Classic 2.3.3 IPA downloaded and independently inspected: build 75, minimum iOS 17.4, original bundle ID com.rileytestut.AltStore, 40,615,381 bytes, SHA-256 3bcfc4ef816abf1551ab31304040d8d556382657663e1f0b720d1a505ca8aca9.
- Version, checksum, device identity, cancellation races, certificate preservation, ADI preservation, redacted errors and 2FA request binding have focused regressions.
- The local native packaging build was stopped because of insufficient disk space; package builds are delegated to CI. This is not evidence of a successful native launch.

## Physical acceptance still required

Use a backed-up device and the same Apple account as its current Nanashi installation. Verify Apple authentication, no certificate revocation, prepared AltStore opening, Remote AltServer activation, Nanashi installation without a new identity, historical data, Health/widget permissions and a real renewal. Unit tests and browser mocks do not satisfy these checks.

## Primary implementation references

- https://github.com/nab138/iloader/tree/v2.4.1
- https://github.com/nab138/isideload (implementation audited at crate 0.5.2; keep Cargo.lock)
- https://cdn.altstore.io/file/altstore/apps.json
- https://github.com/altstoreio/AltStore/tree/classic
- https://github.com/altstoreio/AltStore/blob/v2.3/AltStore/Operations/AuthenticationOperation.swift
- https://github.com/altstoreio/AltStore/blob/v2.3/AltStore/Settings/RemoteAltServerSetupView.swift
- https://github.com/altstoreio/AltStore/blob/v2.3/AltStore/Operations/InstallAppOperation.swift
- https://github.com/altstoreio/FAQ/blob/main/altstore-classic/remote-altservers.md

AltStore 2.3.3's actual IPA reads Documents/ALTPairingFile.plist, not the older ALTPairingFile.dat format emitted by isideload. It reads ALTDeviceID with uppercase ID. The installer supplies both required pieces through the supported installation/container path. It does not transfer an Apple password to the phone.
