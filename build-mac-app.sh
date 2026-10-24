#!/usr/bin/env bash
set -e

# ==============================================================================
# AppShield for macOS: Build & DMG Packaging Script
# Produces:
# 1. AppShield.app (Universal Binary for Intel & Apple Silicon Macs)
# 2. AppShield-macOS.dmg (Standard macOS Drag-to-Install Disk Image)
# ==============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "===================================================================="
echo "         Building AppShield for macOS (App & DMG Packaging)         "
echo "===================================================================="

APP_NAME="AppShield.app"
APP_DIR="$SCRIPT_DIR/$APP_NAME"
CONTENTS_DIR="$APP_DIR/Contents"
MACOS_DIR="$CONTENTS_DIR/MacOS"
RESOURCES_DIR="$CONTENTS_DIR/Resources"

echo "[+] Preparing $APP_NAME structure..."
rm -rf "$APP_DIR"
mkdir -p "$MACOS_DIR"
mkdir -p "$RESOURCES_DIR/static"

# Step 1: Compile Native Universal Cocoa Binary
echo "[+] Compiling Universal Binary (arm64 + x86_64)..."
clang -O2 -arch arm64 -arch x86_64 \
    -framework Cocoa -framework WebKit \
    "$SCRIPT_DIR/AppShield.MacApp/main.m" \
    -o "$MACOS_DIR/AppShield"

chmod +x "$MACOS_DIR/AppShield"

# Step 2: Assemble Resources
echo "[+] Bundling resources and setup engine..."
cp "$SCRIPT_DIR/AppShield.MacApp/static/setup.html" "$RESOURCES_DIR/static/"
cp "$SCRIPT_DIR/AppShield.MacAgent/agent.py" "$RESOURCES_DIR/"
cp "$SCRIPT_DIR/install-mac-agent.sh" "$RESOURCES_DIR/"
cp "$SCRIPT_DIR/uninstall-mac-agent.sh" "$RESOURCES_DIR/"

if [ -f "$SCRIPT_DIR/AppShield.MacApp/AppIcon.icns" ]; then
    cp "$SCRIPT_DIR/AppShield.MacApp/AppIcon.icns" "$RESOURCES_DIR/AppIcon.icns"
fi

# Step 3: Write Info.plist
cat << EOF > "$CONTENTS_DIR/Info.plist"
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleExecutable</key>
    <string>AppShield</string>
    <key>CFBundleIdentifier</key>
    <string>com.appshield.mac</string>
    <key>CFBundleName</key>
    <string>AppShield</string>
    <key>CFBundleDisplayName</key>
    <string>AppShield</string>
    <key>CFBundlePackageType</key>
    <string>APPL</string>
    <key>CFBundleShortVersionString</key>
    <string>1.3.2</string>
    <key>CFBundleVersion</key>
    <string>1.3.2</string>
    <key>CFBundleIconFile</key>
    <string>AppIcon</string>
    <key>LSMinimumSystemVersion</key>
    <string>10.15</string>
    <key>NSHighResolutionCapable</key>
    <true/>
</dict>
</plist>
EOF

# Step 4: Create Distribution Packages (ZIP & DMG)
echo "[+] Packaging AppShield-macOS.zip..."
rm -f "$SCRIPT_DIR/AppShield-macOS.zip"
(cd "$SCRIPT_DIR" && zip -r -q "AppShield-macOS.zip" "$APP_NAME")

echo "[+] Creating standard macOS Disk Image (AppShield-macOS.dmg)..."
DMG_OUTPUT="$SCRIPT_DIR/AppShield-macOS.dmg"
DMG_STAGING="$SCRIPT_DIR/.dmg_staging"
rm -rf "$DMG_STAGING"
rm -f "$DMG_OUTPUT"
mkdir -p "$DMG_STAGING"
cp -R "$APP_DIR" "$DMG_STAGING/"

if hdiutil create -volname "AppShield" -srcfolder "$DMG_STAGING" -ov -format UDZO "$DMG_OUTPUT" 2>/dev/null; then
    echo "[+] AppShield-macOS.dmg created successfully."
fi
rm -rf "$DMG_STAGING"

# Copy into organized Installers/macOS folder
mkdir -p "$SCRIPT_DIR/Installers/macOS"
rm -rf "$SCRIPT_DIR/Installers/macOS/$APP_NAME"
cp -R "$APP_DIR" "$SCRIPT_DIR/Installers/macOS/$APP_NAME"
cp "$SCRIPT_DIR/AppShield-macOS.zip" "$SCRIPT_DIR/Installers/macOS/" 2>/dev/null || true
if [ -f "$DMG_OUTPUT" ]; then
    cp "$DMG_OUTPUT" "$SCRIPT_DIR/Installers/macOS/AppShield-macOS.dmg" 2>/dev/null || true
fi

# Step 5: Install to /Applications and Desktop
echo "[+] Syncing AppShield.app to /Applications and Desktop..."
if [ -d "/Applications" ]; then
    rm -rf "/Applications/$APP_NAME" 2>/dev/null || true
    cp -R "$APP_DIR" "/Applications/$APP_NAME" 2>/dev/null || true
fi

if [ -d "$HOME/Desktop" ]; then
    rm -rf "$HOME/Desktop/$APP_NAME" 2>/dev/null || true
    cp -R "$APP_DIR" "$HOME/Desktop/$APP_NAME" 2>/dev/null || true
    if [ -f "$DMG_OUTPUT" ]; then
        cp "$DMG_OUTPUT" "$HOME/Desktop/AppShield-macOS.dmg" 2>/dev/null || true
    fi
fi

# Clean up build staging dir
rm -rf "$APP_DIR"

echo ""
echo "===================================================================="
echo "              macOS BUILD & PACKAGING COMPLETE!                     "
echo "===================================================================="
echo " 1. Standard Mac App:    /Applications/AppShield.app"
echo " 2. Desktop Shortcut:    ~/Desktop/AppShield.app"
echo " 3. Distribution ZIP:    ~/Desktop/AppShield-macOS.zip"
echo "===================================================================="
