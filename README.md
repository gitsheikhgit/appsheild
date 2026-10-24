# AppShield 🛡️
### Tamper-Resistant Fleet Parental Control, Family DNS Filtering & Application Shield

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Windows%2010%20%2F%2011%20(x64)%20%7C%20macOS-informational)](#system-requirements)
[![Framework](https://img.shields.io/badge/.NET-8.0%20LTS-purple)](https://dotnet.microsoft.com/)
[![Backend](https://img.shields.io/badge/Central%20Server-FastAPI%20%7C%20WebSocket-009688)](https://fastapi.tiangolo.com/)
[![Tailscale Ready](https://img.shields.io/badge/Tailscale-Remote%20Parent%20Access%20Ready-green)](https://tailscale.com/)
[![Zero Telemetry](https://img.shields.io/badge/Privacy-100%25%20Self--Hosted%20%7C%20Zero%20Third--Party%20Tracking-success)](#privacy-architecture)

**AppShield** is an enterprise-grade, self-hosted parental management and endpoint protection suite designed for home networks with shared computers. It addresses the common bypass mechanisms that tech-savvy kids use to defeat consumer parental controls (process renaming, portable executables downloaded to Desktop/Downloads, task manager termination, VPN disablement) through native OS kernel APIs, Session 0 service isolation, and automated network-wide family DNS filtering.

Parents manage every computer on their home network through a unified, modern web console accessible from any smartphone, tablet, or browser.

---

## 🌟 What Makes AppShield Different?

| Common Parental Control Vulnerability | How AppShield Solves It |
| :--- | :--- |
| **Kids rename `game.exe` to `calc.exe`** | **3-Layer Anti-Rename Engine**: AppShield checks Process Name, PE Header `OriginalFilename`, and cached SHA-256 binary hash. Renamed files are terminated within 500ms. |
| **Kids download portable `.exe` files into Downloads/Desktop** | **Path Jail**: Blocks unauthorized executables running out of `%USERPROFILE%\Downloads`, `%APPDATA%`, `Desktop`, `Temp`, or USB flash drives. |
| **Kids kill parental software in Task Manager** | **Session 0 Windows Service & Root macOS Daemon**: Runs as `NT AUTHORITY\SYSTEM` and `root` respectively (`CanStop = false`), completely unkillable by non-admin accounts. |
| **Kids access adult content in incognito or new browsers** | **Family Web & DNS Shield**: Applies network-level domain filtering (Cloudflare Families, CleanBrowsing, AdGuard) directly onto the OS network adapters, enforcing SafeSearch and blocking pornography across all browsers without extensions. |
| **Complex VPN setups on every child PC** | **Central Server Tailscale Topology**: Tailscale is only installed on the parent's Central Server. Child computers connect over standard local LAN with zero configuration. |

---

## 🏛️ Architecture & Network Topology

AppShield uses an outbound-only WebSocket & REST telemetry architecture. Child computers automatically connect to the Central Server upon boot, requiring **zero port forwarding and zero incoming firewall ports** on child machines.

```
                                  [Parent Smartphone / Laptop]
                                               │
                                               │ (Encrypted WireGuard)
                                               ▼
                                      [Tailscale Mesh Network]
                                               │
                                               ▼
                                 ┌───────────────────────────┐
                                 │  AppShield Central Server  │
                                 │   (Proxmox / Docker / LXC) │
                                 │   Port 8000 (FastAPI + WS) │
                                 └─────────────┬─────────────┘
                                               │
                       Local Home LAN (192.168.x.x) - Direct Outbound Only
                                               │
                     ┌─────────────────────────┴─────────────────────────┐
                     ▼                                                   ▼
      ┌─────────────────────────────┐                     ┌─────────────────────────────┐
      │   Windows 10/11 Endpoint    │                     │       macOS Endpoint        │
      │   (Session 0 Background)    │                     │   (/Library/AppShield root) │
      ├─────────────────────────────┤                     ├─────────────────────────────┤
      │ • AppShield.Service.exe     │                     │ • com.appshield.macagent    │
      │ • Native Path Jail          │                     │ • Launch Services Filter    │
      │ • Real-time WebSocket Relay │                     │ • Real-time WebSocket Relay │
      │ • Automated DNS Enforcer    │                     │ • Automated DNS Enforcer    │
      └─────────────────────────────┘                     └─────────────────────────────┘
```

### 🔑 The Tailscale Advantage: Zero Installation on Child PCs

A common headache with remote parental controls is configuring VPN profiles on kids' computers. Kids frequently disable VPN profiles or experience internet dropouts.

**With AppShield:**
1. **Tailscale runs exclusively on the Central Server** (e.g., your Proxmox LXC container, Raspberry Pi, or private server). The server receives a private Tailscale IP (e.g., `100.x.y.z`).
2. **You install Tailscale on YOUR smartphone or parent laptop.** From anywhere in the world (cellular data, hotel Wi-Fi, office network), opening `http://100.x.y.z:8000` gives you instant real-time access to the console.
3. **Child computers DO NOT have Tailscale installed.** They communicate locally to `http://192.168.x.x:8000`. Their connection is lightweight, tamper-free, and cannot be turned off.

---

## 🛡️ Core Features

### 1. 🛡️ Family Web & DNS Shield (Adult & Nudity Protection)
Eliminates adult websites, explicit content, and malicious domains across every browser (Chrome, Edge, Safari, Firefox, Opera) without needing third-party browser extensions.
- **Cloudflare Families (1.1.1.3 / 1.0.0.3)**: High-speed Anycast filtering blocking pornography and malware.
- **CleanBrowsing Family Filter (185.228.168.168 / 185.228.169.168)**: Enforces Google, Bing, and YouTube SafeSearch while blocking adult content and proxy/VPN evasion sites.
- **AdGuard Family Protection (94.140.14.15 / 94.140.15.16)**: Blocks adult content and removes intrusive popup ads and tracker domains.
- **OpenDNS FamilyShield (208.67.222.123 / 208.67.220.123)**: Cisco-backed family protection.
- **Custom DNS Provider**: Direct support for your own NextDNS endpoint or private Pi-hole instance.
- **1-Click Fleet Push**: Enforce DNS settings on a single computer or across every computer on your network simultaneously.

### 2. 📱 Clean Application Drawer (No Process Clutter)
Parents recognize software by friendly names—not cryptic OS background threads.
- Automatically filters out Session 0 Windows services (`svchost.exe`, `csrss.exe`, `lsass.exe`, `RuntimeBroker.exe`).
- Displays clean, recognizable user applications (e.g., `Roblox`, `Google Chrome`, `Steam`, `Discord`, `Minecraft`, `Spotify`).
- Instant remote termination: 1-click **End Process** dispatches an immediate `SIGKILL` to the child's machine.

### 3. 🔒 Path Jail & Child Account Sandboxing
- Prevents standard child accounts from downloading standalone `.exe` files or running unapproved games from `%USERPROFILE%\Downloads`, `Desktop`, `%APPDATA%`, or USB drives.
- **1-Click Standard Account Creator**: Easily provision restricted standard user accounts for children directly from the web console.

### 4. ⏱️ Curfews, Allowed Windows & Quotas
- **🟢 Allowed Hours Window**: Specify exact hours when an app is permitted (e.g., Roblox or Steam allowed **ONLY from 12:00 PM to 8:00 PM**). The application is terminated automatically outside this window.
- **⛔ Bedtime / Downtime Block**: Restrict entertainment applications during nighttime hours.
- **⏱️ Daily Time Quotas**: Tracks active foreground execution in minutes; warns child before terminating the process when the quota expires.

### 5. 🚨 Screen Lock & Remote Emergency Freeze
- 1-click **Lock Screen** instantly invokes `LockWorkStation` on Windows or `SACLockScreenImmediate` on macOS, freezing the computer until unlocked by the parent.

---

## 🚀 Quick Start Guide

### Step 1: Central Server Deployment

The Central Server runs on any Linux host (Proxmox LXC, Debian/Ubuntu, Raspberry Pi, Docker, or Cloud VM).

```bash
# 1. Clone repository
git clone https://github.com/gitsheikhgit/appsheild.git /opt/appshield-server
cd /opt/appshield-server

# 2. Install dependencies
python3 -m venv .venv
source .venv/bin/activate
pip install fastapi uvicorn pydantic websockets

# 3. Start the server (or enable as systemd service)
python3 AppShield.CentralServer/server.py
```

The Web Console is now live at `http://YOUR-SERVER-IP:8000`.

---

### Step 2: Windows Endpoint Installation

1. On the child's Windows 10/11 computer, open a browser and navigate to:
   ```
   http://YOUR-SERVER-IP:8000/download/windows
   ```
2. Download `AppShield-Setup.exe` (Standalone self-contained installer).
3. Right-click and select **Run as administrator**.
4. The installer automatically:
   - Installs `AppShield.Service.exe` into `C:\Program Files\AppShield\`.
   - Registers the un-killable background Windows Service.
   - Connects outbound to your Central Server.
   - Creates an uninstaller in Windows `Settings > Apps > Installed apps`.

---

### Step 3: macOS Endpoint Installation

1. On the child's Mac, open Terminal and run the installer:
   ```bash
   curl -fsSL http://YOUR-SERVER-IP:8000/download/mac -o /tmp/install-appshield.sh
   sudo bash /tmp/install-appshield.sh
   ```
2. The agent installs as a root daemon (`com.appshield.macagent`) under `/Library/Application Support/AppShield/agent/` and connects to the Central Server over WebSocket.

---

## 🌐 Remote Access Setup via Tailscale

To manage your computers when you are away from home:

1. Install Tailscale on the **Central Server** machine:
   ```bash
   curl -fsSL https://tailscale.com/install.sh | sh
   sudo tailscale up
   ```
2. Note the assigned Tailscale IP address (e.g., `100.85.120.44`).
3. Install Tailscale on your iPhone, Android, or laptop from [tailscale.com/download](https://tailscale.com/download).
4. Log into the same Tailscale account.
5. Open your browser and navigate to:
   ```
   http://100.x.y.z:8000
   ```
You now have full remote control of your fleet from anywhere in the world!

---

## 🛠️ Building from Source

### Prerequisites
- macOS 12+ or Linux with .NET 8.0 SDK installed
- Python 3.9+

### Compiling Windows & Mac Binaries
```bash
# Run the master compilation script on macOS
./build-on-mac.sh
```
This produces:
- `dist/Windows-Client-Deploy/AppShield-Setup.exe` (Self-contained single-file Windows installer)
- `dist/Windows-Client-Deploy/AppShield.Service.exe` (.NET 8 Session 0 background daemon)
- `dist/Windows-Client-Deploy/AppShield.Prompt.exe` (.NET 8 WinForms interactive dialog)
- `dist/Windows-Client-Deploy/AppShield-Windows-Install.zip` (Offline deployment bundle)

---

## 🔒 Privacy & Security Guarantee

- **100% Self-Hosted**: All databases, logs, and rules reside on your own local server. Zero telemetry is collected or sent to any corporate third-party servers.
- **Outbound-Only Connections**: Child computers only initiate outbound connections to your server. No open ports are required on child machines.
- **Clean Uninstallation**: Can be completely and cleanly uninstalled at any time from Windows Settings or via `Uninstall-AppShield.ps1` with zero leftover system artifacts.

---

## 🚀 What's New in v1.3.0

- **Fleet Computer Management & Deletion**: Parents can permanently delete any managed or offline computer directly from the Central Server dashboard with type-to-confirm `DELETE` protection.
- **Uninstaller Server Purge Signal**: Uninstallation via GUI or `uninstall-mac-agent.sh` sends an automated unregister signal to Central Server (`/api/devices/unregister` and `DELETE /api/fleet/{id}`) to purge the device from database tables.
- **Installer Existing Installation Detection**: Re-running the macOS installer detects an existing active daemon and presents options to **Update / Overwrite** core binaries, **Open** the installed app, or **Uninstall** cleanly.
- **Native High-Resolution Application Icons**: Added Cocoa icon extraction caching real 48x48 PNG icons for both installed and active applications across client and server views.
- **Bulletproof Standalone Decoupling**: Parents can disconnect a Mac from Central Server into 100% local standalone mode with `DELETE` confirmation without disrupting local schedules.

---

## 📄 License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.
