#!/usr/bin/env bash
# Package a validated universal app without Finder or AppleScript automation.
set -euo pipefail

expected_version="${1:?Pass the expected installer version.}"
repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
app_bundle="$repo_root/src-tauri/target/universal-apple-darwin/release/bundle/macos/Nanashi Installer.app"
info_plist="$app_bundle/Contents/Info.plist"
artifact_directory="$repo_root/release-artifacts"
recovery_directory="$repo_root/build/ci-recovery"

if [[ "$(uname -s)" != 'Darwin' ]]; then
  echo 'macOS is required for DMG packaging.' >&2
  exit 1
fi
if [[ ! -d "$app_bundle" || ! -f "$info_plist" ]]; then
  echo 'The universal macOS app was not produced.' >&2
  exit 1
fi

configured_version="$(node -p 'require(process.argv[1]).version' "$repo_root/src-tauri/tauri.conf.json")"
bundle_version="$(/usr/libexec/PlistBuddy -c 'Print :CFBundleShortVersionString' "$info_plist")"
bundle_identifier="$(/usr/libexec/PlistBuddy -c 'Print :CFBundleIdentifier' "$info_plist")"
bundle_executable="$(/usr/libexec/PlistBuddy -c 'Print :CFBundleExecutable' "$info_plist")"
if [[ "$configured_version" != "$expected_version" || "$bundle_version" != "$expected_version" ]]; then
  echo 'The configured and built versions must match the release version.' >&2
  exit 1
fi
if [[ "$bundle_identifier" != 'com.rayanmakhlouf.nanashi.installer' || -z "$bundle_executable" || "$bundle_executable" == */* ]]; then
  echo 'The bundle identity or executable is invalid.' >&2
  exit 1
fi
binary="$app_bundle/Contents/MacOS/$bundle_executable"
if [[ ! -f "$binary" || ! -x "$binary" ]]; then
  echo 'The app executable is missing.' >&2
  exit 1
fi
architecture_output="$(xcrun lipo -archs "$binary")"
read -r -a architectures <<< "$architecture_output"
if [[ " ${architectures[*]} " != *' arm64 '* || " ${architectures[*]} " != *' x86_64 '* ]]; then
  echo 'The app executable must contain both arm64 and x86_64 architectures.' >&2
  exit 1
fi

mkdir -p "$artifact_directory" "$recovery_directory"
stage_directory="$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/nanashi-dmg.XXXXXX")"
trap 'rm -rf -- "$stage_directory"' EXIT

mkdir "$stage_directory/content"
staged_app="$stage_directory/content/Nanashi Installer.app"
ditto "$app_bundle" "$staged_app"
# This preview has no Developer ID identity. Seal both executable slices and
# the resources together so each architecture can verify the same app bundle.
codesign --force --sign - --timestamp=none "$staged_app"
codesign --verify --deep --strict --all-architectures "$staged_app"

# Keep a validated .app archive even if disk-image creation fails later. This
# is a CI recovery artifact, not a replacement for the verified release DMG.
ditto -c -k --sequesterRsrc --keepParent "$staged_app" "$stage_directory/mac-app.zip"
mv -f -- "$stage_directory/mac-app.zip" "$recovery_directory/Nanashi-Installer-macOS-app.zip"

ln -s /Applications "$stage_directory/content/Applications"
hdiutil create -volname 'Nanashi Installer' -fs HFS+ -format UDZO \
  -srcfolder "$stage_directory/content" "$stage_directory/Nanashi-Installer-macOS.dmg"
hdiutil verify "$stage_directory/Nanashi-Installer-macOS.dmg"
mv -f -- "$stage_directory/Nanashi-Installer-macOS.dmg" "$artifact_directory/Nanashi-Installer-macOS.dmg"
echo "Packaged Nanashi Installer $expected_version for arm64 and x86_64."
