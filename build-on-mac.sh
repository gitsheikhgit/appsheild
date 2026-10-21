#!/usr/bin/env bash
set -e

# ==============================================================================
# AppShield: Master Cross-Compilation & Packaging Script for macOS
# Builds Windows 10/11 (win-x64) binaries & prepares the Admin Control Dashboard
# ==============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "===================================================================="
echo "    AppShield: macOS-to-Windows Cross-Compilation & Packaging       "
echo "===================================================================="
echo ""

# Ensure .NET 8 is in PATH (check /usr/local/share/dotnet first, then ~/.dotnet)
if [ -d "/usr/local/share/dotnet" ]; then
    export PATH="/usr/local/share/dotnet:$PATH"
    export DOTNET_ROOT="/usr/local/share/dotnet"
elif [ -d "$HOME/.dotnet" ]; then
    export PATH="$HOME/.dotnet:$PATH"
    export DOTNET_ROOT="$HOME/.dotnet"
fi

if ! command -v dotnet >/dev/null 2>&1; then
    echo "[-] Error: .NET SDK not found. Please install .NET 8 SDK or run dotnet-install.sh"
    exit 1
fi

DOTNET_VER=$(dotnet --version)
echo "[+] Detected .NET SDK version: $DOTNET_VER"

# Step 1: Clean and Prepare Distribution Directory
DIST_DIR="$SCRIPT_DIR/dist/Windows-Client-Deploy"
echo "[+] Preparing distribution directory: $DIST_DIR"
rm -rf "$SCRIPT_DIR/dist"
mkdir -p "$DIST_DIR"

# Step 2: Cross-Compile AppShield.Service for win-x64
echo "[+] Cross-compiling AppShield.Service (Session 0 Headless Worker & Kestrel API)..."
dotnet publish "$SCRIPT_DIR/AppShield.Client/AppShield.Service/AppShield.Service.csproj" \
    -c Release \
    -r win-x64 \
    --self-contained true \
    -p:PublishSingleFile=true \
    -p:IncludeNativeLibrariesForSelfExtract=true \
    -p:EnableWindowsTargeting=true \
    -o "$SCRIPT_DIR/AppShield.Client/AppShield.Service/bin/publish-win64"

# Step 3: Cross-Compile AppShield.Prompt for win-x64
echo "[+] Cross-compiling AppShield.Prompt (Interactive Desktop WinForms Password Prompt)..."
dotnet publish "$SCRIPT_DIR/AppShield.Client/AppShield.Prompt/AppShield.Prompt.csproj" \
    -c Release \
    -r win-x64 \
    --self-contained true \
    -p:PublishSingleFile=true \
    -p:IncludeNativeLibrariesForSelfExtract=true \
    -p:EnableWindowsTargeting=true \
    -o "$SCRIPT_DIR/AppShield.Client/AppShield.Prompt/bin/publish-win64"

# Step 4: Cross-Compile AppShield.Installer (Single Standalone Executable AppShield-Setup.exe)
echo "[+] Creating payload archive for single-file installer..."
cp "$SCRIPT_DIR/AppShield.Client/AppShield.Installer/appshield.ico" "$DIST_DIR/"
zip -j "$SCRIPT_DIR/AppShield.Client/AppShield.Installer/payload.zip" \
    "$SCRIPT_DIR/AppShield.Client/AppShield.Service/bin/publish-win64/AppShield.Service.exe" \
    "$SCRIPT_DIR/AppShield.Client/AppShield.Prompt/bin/publish-win64/AppShield.Prompt.exe" \
    "$SCRIPT_DIR/AppShield.Client/AppShield.Installer/appshield.ico"

echo "[+] Cross-compiling AppShield.Installer (AppShield-Setup.exe)..."
dotnet publish "$SCRIPT_DIR/AppShield.Client/AppShield.Installer/AppShield.Installer.csproj" \
    -c Release \
    -r win-x64 \
    --self-contained true \
    -p:PublishSingleFile=true \
    -p:IncludeNativeLibrariesForSelfExtract=true \
    -p:EnableWindowsTargeting=true \
    -o "$SCRIPT_DIR/AppShield.Client/AppShield.Installer/bin/publish-win64"

# Step 5: Package Windows Client Deployment Folder
echo "[+] Packaging standalone executables and launchers into dist/Windows-Client-Deploy/..."
cp "$SCRIPT_DIR/AppShield.Client/AppShield.Service/bin/publish-win64/AppShield.Service.exe" "$DIST_DIR/"
cp "$SCRIPT_DIR/AppShield.Client/AppShield.Prompt/bin/publish-win64/AppShield.Prompt.exe" "$DIST_DIR/"
cp "$SCRIPT_DIR/AppShield.Client/AppShield.Installer/bin/publish-win64/AppShield-Setup.exe" "$DIST_DIR/"
if [ -d "$HOME/Desktop" ]; then
    cp "$SCRIPT_DIR/AppShield.Client/AppShield.Installer/bin/publish-win64/AppShield-Setup.exe" "$HOME/Desktop/AppShield-Setup.exe" || true
fi
cp "$SCRIPT_DIR/Install-AppShield.ps1" "$DIST_DIR/"
cp "$SCRIPT_DIR/Uninstall-AppShield.ps1" "$DIST_DIR/"

# Package into ZIP archive for USB transfer
echo "[+] Creating AppShield-Windows-Install.zip..."
(cd "$SCRIPT_DIR/dist" && zip -r "$DIST_DIR/AppShield-Windows-Install.zip" Windows-Client-Deploy)
if [ -d "$HOME/Desktop" ]; then
    cp "$DIST_DIR/AppShield-Windows-Install.zip" "$HOME/Desktop/AppShield-Windows-Install.zip" || true
fi
cp "$DIST_DIR/AppShield-Windows-Install.zip" "$SCRIPT_DIR/AppShield-Windows-Install.zip" || true

echo "[+] Successfully packaged Windows client binaries and AppShield-Setup.exe:"
ls -lh "$DIST_DIR"


# Step 5: Configure Admin Control Dashboard Python Virtual Environment
echo ""
echo "[+] Setting up Admin Control Dashboard Python virtual environment..."
ADMIN_DIR="$SCRIPT_DIR/AppShield.Admin"
VENV_DIR="$ADMIN_DIR/.venv"

if ! command -v python3 >/dev/null 2>&1; then
    echo "[-] Warning: python3 not found. Skipping venv setup."
else
    if [ ! -d "$VENV_DIR" ]; then
        echo "    Creating virtual environment at $VENV_DIR..."
        python3 -m venv "$VENV_DIR"
    fi

    echo "    Installing/verifying Python dependencies..."
    "$VENV_DIR/bin/pip" install --upgrade pip --quiet
    "$VENV_DIR/bin/pip" install -r "$ADMIN_DIR/requirements.txt" --quiet
    echo "    Python virtual environment is ready."
fi

# Step 6: Compile Native macOS Cocoa Desktop Application
echo "[+] Compiling Native macOS Cocoa App (Universal arm64/x86_64)..."
mkdir -p "$SCRIPT_DIR/AppShield Admin.app/Contents/MacOS"
clang -O2 -arch arm64 -arch x86_64 -framework Cocoa -framework WebKit \
    "$SCRIPT_DIR/AppShield.Admin/native_mac/main.m" \
    -o "$SCRIPT_DIR/AppShield Admin.app/Contents/MacOS/AppShield Admin"
chmod +x "$SCRIPT_DIR/AppShield Admin.app/Contents/MacOS/AppShield Admin"

# Install native app to Desktop and /Applications if permitted
if [ -d "$HOME/Desktop" ]; then
    rm -rf "$HOME/Desktop/AppShield Admin.app"
    cp -R "$SCRIPT_DIR/AppShield Admin.app" "$HOME/Desktop/AppShield Admin.app" || true
    (cd "$SCRIPT_DIR" && zip -r "$HOME/Desktop/AppShield-Admin-macOS.zip" "AppShield Admin.app" >/dev/null 2>&1 || true)
fi
if [ -d "/Applications" ]; then
    rm -rf "/Applications/AppShield Admin.app" 2>/dev/null || true
    cp -R "$SCRIPT_DIR/AppShield Admin.app" "/Applications/AppShield Admin.app" 2>/dev/null || true
fi

# Step 7: Create/Update Double-Clickable macOS Launcher
echo "[+] Creating double-clickable macOS Admin launcher: run-admin-mac.command..."
cat << 'EOF' > "$SCRIPT_DIR/run-admin-mac.command"
#!/usr/bin/env bash
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
open "$SCRIPT_DIR/AppShield Admin.app"
EOF

chmod +x "$SCRIPT_DIR/run-admin-mac.command"
chmod +x "$SCRIPT_DIR/build-on-mac.sh"

echo ""
echo "===================================================================="
echo "                    BUILD & PACKAGING COMPLETE!                     "
echo "===================================================================="
echo " 1. Native macOS App:          AppShield Admin.app (Desktop & Applications)"
echo " 2. Windows deployment bundle: dist/Windows-Client-Deploy/"
echo " 3. macOS Admin launcher:      ./run-admin-mac.command"
echo "===================================================================="

