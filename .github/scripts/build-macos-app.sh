#!/bin/bash
# Build (and optionally sign+notarize) Clawpatrol.app for distribution.
#
# Without APPLE_ID set: produces an unsigned build (used for PR checks
# and local dev verification). With all the APPLE_* secrets set, signs
# with Developer ID Application + notarizes via notarytool + staples.
#
# Output: macos/Clawpatrol.app.tar.gz
set -euo pipefail

TEAM_ID="2H4KBF436B"
SCHEME="Clawpatrol"
PROJECT="macos/Clawpatrol.xcodeproj"
EXPORT_OPTIONS="macos/ExportOptions.plist"
BUILD_DIR="build"

build_netstack() {
  # Clawpatrol's macOS extension links libwgnetstack.a — a Go cgo
  # c-archive bundling wireguard-go + gVisor netstack. Built outside
  # the Xcode project so CI doesn't need brew-go in the Xcode shell
  # phase.
  pushd macos/netstack >/dev/null
  CGO_ENABLED=1 GOOS=darwin GOARCH=arm64 \
    go build -buildmode=c-archive -o libwgnetstack.a .
  popd >/dev/null
}

# bump_build_number stamps CFBundleVersion = git commit count on both
# the .app and extension Info.plists. sysextd treats system extensions
# with the same (CFBundleShortVersionString, CFBundleVersion) tuple as
# the running one as a no-op activation, so without a bump here a
# `Clawpatrol install` after an in-place .app replacement leaves the
# old extension binary running. Commit count is monotonic across
# rebuilds; sysextd accepts the higher number and swaps the ext.
bump_build_number() {
  # CFBundleShortVersionString = release tag (`v0.1.2` → `0.1.2`).
  # CFBundleVersion bumps too. sysextd treats the (short, build) tuple
  # as the ext identity — same tuple = no-op activation, leaves the
  # running ext in place. Bumping short to the release tag forces
  # sysextd to swap on next `Clawpatrol install`.
  #
  # Local dev builds (no RELEASE_TAG) fall back to a timestamp so
  # iterating builds also rotates the version.
  local v
  if [ -n "${RELEASE_TAG:-}" ]; then
    v="${RELEASE_TAG#v}"
  else
    v="0.0.$(date +%s)"
  fi
  /usr/bin/plutil -replace CFBundleShortVersionString -string "$v" \
    macos/Clawpatrol/Info.plist
  /usr/bin/plutil -replace CFBundleShortVersionString -string "$v" \
    macos/ClawpatrolExtension/Info.plist
  /usr/bin/plutil -replace CFBundleVersion -string "$v" \
    macos/Clawpatrol/Info.plist
  /usr/bin/plutil -replace CFBundleVersion -string "$v" \
    macos/ClawpatrolExtension/Info.plist
  echo "==> CFBundleShortVersionString = CFBundleVersion = $v"
}

# If no Apple ID, build unsigned (local dev / PR checks).
if [ -z "${APPLE_ID:-}" ]; then
  echo "==> Building unsigned (no APPLE_ID set)"
  build_netstack
  bump_build_number
  brew install xcodegen 2>/dev/null || true
  xcodegen --spec macos/project.yml
  xcodebuild \
    -project "$PROJECT" \
    -scheme "$SCHEME" \
    -configuration Release \
    -arch arm64 ONLY_ACTIVE_ARCH=NO \
    CODE_SIGN_IDENTITY="-" \
    CODE_SIGNING_REQUIRED=NO \
    CODE_SIGN_ALLOW_ENTITLEMENTS_MODIFICATION=YES \
    PROVISIONING_PROFILE_SPECIFIER="" \
    build

  APP_OUTPUT=$(xcodebuild -project "$PROJECT" -scheme "$SCHEME" -configuration Release -showBuildSettings 2>/dev/null \
    | awk '/ BUILT_PRODUCTS_DIR /{print $3}' | head -1)
  mkdir -p macos
  tar -czf "macos/Clawpatrol.app.tar.gz" -C "$APP_OUTPUT" "Clawpatrol.app"
  echo "==> Unsigned build: macos/Clawpatrol.app.tar.gz"
  exit 0
fi

echo "==> Building signed + notarized"

# 1. Temporary keychain for the signing identity.
KEYCHAIN_PATH="$RUNNER_TEMP/app-signing.keychain"
security create-keychain -p "app-signing" "$KEYCHAIN_PATH"
security set-keychain-settings -lut 21600 "$KEYCHAIN_PATH"
security unlock-keychain -p "app-signing" "$KEYCHAIN_PATH"

# 2. Import Developer ID Application cert.
echo -n "$APPLE_CERTIFICATE" | base64 --decode > "$RUNNER_TEMP/cert.p12"
security import "$RUNNER_TEMP/cert.p12" \
  -k "$KEYCHAIN_PATH" \
  -P "$APPLE_CERTIFICATE_PASSWORD" \
  -A
security set-key-partition-list -S apple-tool:,apple: -s -k "app-signing" "$KEYCHAIN_PATH"
security list-keychain -s "$KEYCHAIN_PATH"

# 3. Install Developer ID provisioning profiles.
mkdir -p ~/Library/MobileDevice/Provisioning\ Profiles
echo -n "$APPLE_PROVISIONING_PROFILE_APP" | base64 --decode \
  > ~/Library/MobileDevice/Provisioning\ Profiles/clawpatrol_app.provisionprofile
echo -n "$APPLE_PROVISIONING_PROFILE_EXT" | base64 --decode \
  > ~/Library/MobileDevice/Provisioning\ Profiles/clawpatrol_ext.provisionprofile

# 4. Build the Go cgo netstack archive.
build_netstack
bump_build_number

# 5. Patch project for distribution: switch entitlements to
#    -systemextension variants, swap profile names from dev to release.
for ent in macos/Clawpatrol/Clawpatrol.entitlements macos/ClawpatrolExtension/ClawpatrolExtension.entitlements; do
  sed -i '' \
    -e 's|app-proxy-provider</string>|app-proxy-provider-systemextension</string>|g' \
    "$ent"
done
sed -i '' \
  -e 's/app-proxy-provider$/app-proxy-provider-systemextension/' \
  -e 's/CODE_SIGN_IDENTITY: "Apple Development"/CODE_SIGN_IDENTITY: "Developer ID Application"/' \
  -e 's/Clawpatrol App Dev/Clawpatrol App/' \
  -e 's/Clawpatrol Extension Dev/Clawpatrol Extension/' \
  macos/project.yml
brew install xcodegen 2>/dev/null || true
xcodegen --spec macos/project.yml

# 6. Archive. arm64-only — libwgnetstack.a is built for darwin/arm64
# (apple silicon). Universal would require a separate amd64 build of
# the Go archive + lipo, which we skip until x86_64 macs matter.
xcodebuild \
  -project "$PROJECT" \
  -scheme "$SCHEME" \
  -configuration Release \
  -arch arm64 ONLY_ACTIVE_ARCH=NO \
  -archivePath "$BUILD_DIR/Clawpatrol.xcarchive" \
  OTHER_CODE_SIGN_FLAGS="--keychain $KEYCHAIN_PATH" \
  archive

# 7. Export.
xcodebuild \
  -exportArchive \
  -archivePath "$BUILD_DIR/Clawpatrol.xcarchive" \
  -exportOptionsPlist "$EXPORT_OPTIONS" \
  -exportPath "$BUILD_DIR"

# 8. Notarize.
xcrun notarytool store-credentials "AC_PASSWORD" \
  --keychain "$KEYCHAIN_PATH" \
  --apple-id "$APPLE_ID" \
  --team-id "$TEAM_ID" \
  --password "$APPLE_APP_PASSWORD"

ditto -c -k --keepParent "$BUILD_DIR/Clawpatrol.app" "$BUILD_DIR/Clawpatrol.app.zip"

xcrun notarytool submit \
  "$BUILD_DIR/Clawpatrol.app.zip" \
  --keychain "$KEYCHAIN_PATH" \
  --keychain-profile "AC_PASSWORD" \
  --wait

xcrun stapler staple "$BUILD_DIR/Clawpatrol.app"

# 9. Package.
mkdir -p macos
tar -czf "macos/Clawpatrol.app.tar.gz" -C "$BUILD_DIR" "Clawpatrol.app"

echo "==> Signed + notarized: macos/Clawpatrol.app.tar.gz"
