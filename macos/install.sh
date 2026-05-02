#!/bin/bash
# Build Clawpatrol.app and install to /Applications.
#
# Why a script instead of just `xcodebuild + cp`:
#   sysextd refuses to realize a system extension when LaunchServices'
#   authoritative bundle path for the parent ID resolves outside
#   /Applications. Xcode registers the DerivedData copy on every build,
#   and that registration wins over a manually-copied /Applications copy.
#   We unregister DerivedData explicitly + force-reregister /Applications
#   so sysextd's "/Applications-only" gate (no MDM) passes.
set -euo pipefail

cd "$(dirname "$0")"

LSREGISTER=/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister

echo "▸ xcodebuild"
xcodebuild -project Clawpatrol.xcodeproj -scheme Clawpatrol -configuration Debug build | tail -5

DERIVED=$(xcodebuild -project Clawpatrol.xcodeproj -scheme Clawpatrol -showBuildSettings 2>/dev/null \
  | awk '/ BUILT_PRODUCTS_DIR /{print $3}' | head -1)
SRC="$DERIVED/Clawpatrol.app"

echo "▸ install to /Applications"
sudo rm -rf /Applications/Clawpatrol.app
sudo cp -R "$SRC" /Applications/Clawpatrol.app

# `lsregister -u` is unreliable (silent no-op when LS DB is in
# an inconsistent state). Delete DerivedData copy from disk so
# Xcode doesn't keep re-registering it, then rebuild the LS DB
# from scratch — guarantees only the /Applications path remains
# authoritative. Without this, sysextd may resolve the bundle ID
# to the DerivedData path and reject realize with "no policy,
# cannot allow apps outside /Applications".
echo "▸ purge DerivedData copy + rebuild LaunchServices DB"
rm -rf "$SRC"
"$LSREGISTER" -kill -r -domain local -domain system -domain user >/dev/null 2>&1 || true
"$LSREGISTER" -f /Applications/Clawpatrol.app
# Don't lsregister the .systemextension directly — LS rejects with
# -10811 ("not a recognized bundle"). Sysextd discovers it via the
# parent app's bundle scan, provided the parent's Info.plist has
# NSSystemExtensionUsageDescription set (otherwise sysextd reports
# "Extension not found in App bundle" on activation).

echo "▸ done. run:  /Applications/Clawpatrol.app/Contents/MacOS/Clawpatrol install"
