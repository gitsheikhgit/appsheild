# AppShield 🛡️
### Tamper-Resistant Windows Application Control & Remote Multi-User Endpoint Fleet Management

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Windows%2010%20%2F%2011%20(x64)%20%7C%20macOS-informational)](#system-requirements)
[![Framework](https://img.shields.io/badge/.NET-8.0%20LTS-purple)](https://dotnet.microsoft.com/)
[![Tailscale Ready](https://img.shields.io/badge/Tailscale-Remote%20Access%20Ready-green)](https://tailscale.com/)
[![Zero Telemetry](https://img.shields.io/badge/Privacy-100%25%20Local%20%7C%20Zero%20Cloud%20Telemetry-success)](#privacy-architecture)

**AppShield** is an enterprise-grade endpoint application control and parental management platform designed for shared Windows 10/11 computers. It solves the fundamental bypass mechanisms common to standard parental control tools (process renaming, downloading portable executables into user folders, session evasion, task manager termination) using native Win32 kernel APIs, Session 0 isolation breakout, 3-layer anti-rename process identification, daily runtime quotas, and directory path jails.

Administrators can manage the endpoint locally via the **AppShield Windows Control Center** or remotely from anywhere in the world using the **macOS Admin Dashboard** over a secure **Tailscale** private mesh network.

---

## 📥 Direct Downloads

| Artifact | Description | Direct Download |
| :--- | :--- | :--- |
| **AppShield-Setup.exe** | **Single Standalone Windows Installer & Control Center GUI**. All-in-one executable: installs the service, creates databases, configures firewall rules, and acts as the desktop management interface for Administrators. | [🚀 Download Latest AppShield-Setup.exe](https://github.com/gitsheikhgit/appsheild/releases/latest/download/AppShield-Setup.exe) |
| **AppShield-Windows-Install.zip** | **Full Deployment Bundle**. Contains standalone executables, PowerShell deployment scripts, icon assets, and offline documentation. | [📦 Download AppShield-Windows-Install.zip](https://github.com/gitsheikhgit/appsheild/releases/latest/download/AppShield-Windows-Install.zip) |
| **macOS Admin App** | Source and double-clickable app launcher for macOS (`AppShield Admin.app`). | Clone this repository |
| **All Releases & Tags** | Full version history, changelogs, and release assets. | [🔖 View GitHub Releases](https://github.com/gitsheikhgit/appsheild/releases) |

---

## 📑 Table of Contents

- [The Problem AppShield Solves](#the-problem-appshield-solves)
- [Key Features](#key-features)
- [Architecture & System Design](#architecture--system-design)
- [Quick Start Guide](#quick-start-guide)
  - [1. Windows Installation (Single Executable)](#1-windows-installation-single-executable)
  - [2. macOS Admin Dashboard Setup](#2-macos-admin-dashboard-setup)
- [🌐 Setting Up Tailscale for Remote Access (Step-by-Step)](#-setting-up-tailscale-for-remote-access-step-by-step)
- [Windows Control Center Guide](#windows-control-center-guide)
- [Enforcement Mechanisms](#enforcement-mechanisms)
  - [3-Layer Anti-Rename Detection](#3-layer-anti-rename-detection)
  - [Path Jail (User-Writable Directory Blocking)](#path-jail-user-writable-directory-blocking)
  - [Session 0 Breakout & Native WinForms Prompts](#session-0-breakout--native-winforms-prompts)
- [Security & Tamper Resistance](#security--tamper-resistance)
- [Safe Uninstallation & System Restore](#safe-uninstallation--system-restore)
- [Building from Source](#building-from-source)
- [Privacy Disclosure](#privacy-disclosure)

---

## The Problem AppShield Solves

Standard parental control tools and Windows Family Safety are frequently rendered ineffective by tech-savvy kids through trivial workarounds:
1. **The Rename Trick**: Renaming `discord.exe` or `game.exe` to `calc.exe` or `system.exe` bypasses simple filename filters.
2. **Portable Executables**: Bypassing app restrictions by downloading standalone `.exe` files into `%USERPROFILE%\Downloads`, `%APPDATA%`, or running them directly from a USB stick.
3. **Closing Background Apps**: Standard user-space apps sitting in the system tray can easily be terminated from Windows Task Manager.
4. **Session 0 Disconnect**: Traditional background services cannot interact with the user's desktop, making real-time interactive prompts or temporary overrides impossible without complex multi-process coordination.

**AppShield addresses each vulnerability at the OS architecture level:**
- Runs as an un-killable Windows Service under `NT AUTHORITY\SYSTEM` in Session 0 (`CanStop = false`).
- Inspects PE Headers and cached SHA-256 binary signatures so renamed files are detected instantly.
- Enforces an automated **Path Jail** that immediately terminates unauthorized executables spawned from user-writable directories.
- Breaks out of Session 0 using Win32 API calls (`WTSQueryUserToken`, `DuplicateTokenEx`, `CreateProcessAsUser`) to deliver a high-priority, topmost interactive override dialog to the active user session.

---

## Key Features

- **🚀 Single-Executable Windows Installer (`AppShield-Setup.exe`)**:
  - Zero dependencies or external runtimes required (self-contained .NET 8).
  - Built-in Privacy Disclosure Agreement & custom installation path selector.
  - Generates SQLite database, configures Windows Service, and opens local firewall port 54120.
  - Automatically creates Desktop & Start Menu shortcuts scoped exclusively to the Administrator profile.
- **🖥️ Full Native Administrator Control Center (Windows & macOS)**:
  - Both Windows and macOS offer the **exact same rich, dark-mode management interface** with full feature parity.
  - On Windows: Double-clicking the `AppShield` desktop or Start Menu icon launches a dedicated, frameless standalone window powered by the local background service on port 54121.
  - Protected with Windows UAC administrator elevation and Master Password authentication. Standard (kid) accounts cannot access it.
  - Control live processes, user accounts, path jails, blocked apps, bedtime/allowed schedules, registry-scanned installed apps, and uninstallation from **both Windows and Mac**.
- **🛡️ 3-Layer Anti-Rename Process Detection**:
  - Matches process name (e.g., `discord.exe`).
  - Matches binary metadata PE header `OriginalFilename` (e.g., `Discord.exe` via `FileVersionInfo`).
  - Matches cryptographic SHA-256 binary hash (cached by file path and modification timestamp to preserve CPU performance).
- **🔒 Path Jail (`BlockUserWritableDirectories`)**:
  - Blocks portable and unapproved executables from `%USERPROFILE%\Downloads`, `%USERPROFILE%\Desktop`, `%APPDATA%`, `%LOCALAPPDATA%\Temp`, and removable USB drives.
- **⏱️ Daily Quotas, Allowed Usage Windows & Bedtime Schedules**:
  - **🟢 Allowed Hours Window**: Specify exact hours when an app is permitted (e.g., kid can **ONLY** use games from `12:00 PM to 8:00 PM`). The app is terminated automatically at all other times.
  - **⛔ Bedtime / Downtime Block**: Restrict apps during nighttime hours (e.g., bedtime block from `9:00 PM to 7:00 AM`).
  - **⏱️ Daily Time Quotas**: Tracks active foreground execution in seconds; delivers a 60-second warning countdown before termination (e.g., 60 minutes/day).
  - **🔴 Always Block**: 24/7 immediate process tree termination (`process.Kill(entireProcessTree: true)`).
  - **⚡ Quick 1-Click Presets**: Fast schedule buttons for `12:00 PM – 8:00 PM (Afternoon/Evening)`, `3:00 PM – 8:00 PM (After School)`, `9:00 AM – 5:00 PM (Daytime)`, and Bedtime.
- **🌐 Remote Fleet Management with Dual-IP Failover**:
  - Manage multiple endpoints from a unified macOS Dashboard (`AppShield Admin.app`) or Windows Control Center.
  - Automatic failover between local LAN IP (at home) and Tailscale WireGuard IP (when away).
  - Mutual HTTPS communication with 32-character Pre-Shared Key (PSK) and anti-replay timestamps.
- **🧹 100% Clean Safe Uninstaller**:
  - Registered in Windows Settings (`Settings > Apps > Installed apps`).
  - Stops service, unregisters service, removes firewall rules, cleans shortcuts, and deletes application files without leaving system residue.

---

## Architecture & System Design

```
                     +------------------------------------------------------+
                     |             macOS Admin Dashboard (FastAPI)          |
                     |  - Fleet Manager & mDNS Subnet Discovery             |
                     |  - Tailscale WireGuard Remote Management             |
                     |  - Dark Mode UI (Tailwind CSS + Alpine.js)           |
                     +------------------------------------------------------+
                                                |
                       Mutual HTTPS (Port 54120) with PSK + Timestamp Validation
                                                |
                                                v
    +----------------------------------------------------------------------------------------+
    |                               Target Windows 10/11 Endpoint                            |
    |                                                                                        |
    |  [Session 0: System Service (NT AUTHORITY\SYSTEM)]                                     |
    |  - Tamper-resistant background daemon (CanStop = false)                                |
    |  - Hybrid Process Monitor (WMI Event Trace + 1500ms Fallback Polling)                  |
    |  - Sub-millisecond Win32 Token Lookup via advapi32.dll (OpenProcessToken)              |
    |  - 3-Layer Anti-Rename Engine (Process Name + PE Header + Cached SHA-256)              |
    |  - Path Jail: Blocks Downloads, Desktop, AppData, Temp, USB executables                |
    |  - Daily Quota Tracking & Bedtime Schedule Enforcement                                 |
    |  - SQLite Database locked with NTFS ACLs (SYSTEM/Admin only) and Windows DPAPI         |
    |  - Embedded HTTPS Kestrel Management API (Port 54120)                                  |
    |  - Inter-Process Communication via Named Pipe (\\.\pipe\AppShieldOverridePipe)         |
    |                                                                                        |
    |  [Session 1+: Interactive User Desktop (winsta0\default)]                               |
    |  - Spawned on-demand via WTSQueryUserToken + DuplicateTokenEx + CreateProcessAsUser    |
    |  - AppShield.Prompt.exe (Topmost WinForms Override Dialog with 60s Quota Timer)       |
    |  - Local Emergency Master Password Bypass                                              |
    |                                                                                        |
    |  [Administrator User Profile Only]                                                     |
    |  - AppShield-Setup.exe (Control Center GUI with Master Password Authentication)        |
    |  - Registered Uninstaller in Windows "Installed apps" Settings                         |
    +----------------------------------------------------------------------------------------+
```

---

## Quick Start Guide

### 1. Windows Installation (Single Executable)

1. **Download the installer**:
   Download [AppShield-Setup.exe](https://github.com/gitsheikhgit/appsheild/releases/latest/download/AppShield-Setup.exe) directly to the target Windows 10/11 computer.
2. **Run as Administrator**:
   Right-click `AppShield-Setup.exe` and choose **Run as administrator** (or double-click; Windows UAC will prompt for elevation).
3. **Review Privacy Disclosure & Operational Scope**:
   Review the disclosure confirming zero cloud telemetry, local on-device operation, and system modifications. Check **I accept the terms and privacy disclosure** to proceed.
4. **Configure Settings**:
   - **Installation Directory**: Default is `C:\Program Files\AppShield` (or select custom).
   - **Master Password**: Set a strong password for unlocking the local Control Center and offline overrides.
   - **Pre-Shared Key (PSK)**: A secure 32-character key is generated automatically (copy this key for your macOS Admin dashboard).
   - **Desktop Shortcut**: Check **Create a Desktop icon** to place a shortcut on the Administrator's desktop.
5. **Click Install AppShield**:
   The installer automatically unpacks the binaries, secures the directory with NTFS ACLs, provisions the SQLite database, configures and starts the Windows Service, and registers the uninstaller.

> [!NOTE]
> **Admin Scoping**: The Desktop shortcut and Start Menu shortcut are created in the Administrator's personal user profile (`%USERPROFILE%\Desktop` and `%APPDATA%\Microsoft\Windows\Start Menu\Programs`). Standard user (child) accounts will not see or have access to these shortcuts.

---

### 2. macOS Admin Dashboard Setup

1. **Clone the repository**:
   ```bash
   git clone https://github.com/gitsheikhgit/appsheild.git
   cd appsheild
   ```
2. **Build and package** (if developing or compiling from source):
   ```bash
   ./build-on-mac.sh
   ```
3. **Launch the Admin Dashboard**:
   - Double-click `AppShield Admin.app` from Finder, or
   - Run `./run-admin-mac.command` in Terminal.
4. **Connect to your Windows Endpoint**:
   - In your browser (`http://127.0.0.1:8080`), click **Add Node** or **Scan Subnet (mDNS)**.
   - Enter the target computer's IP address (LAN IP or Tailscale IP) and the 32-character PSK generated during Windows installation.
   - You can now configure rules, adjust quotas, and view real-time audit logs.

---

## 🌐 Setting Up Tailscale for Remote Access (Step-by-Step)

With **Tailscale**, you can monitor, configure, and manage your Windows family computer from anywhere outside your home (from your office, a coffee shop, or while traveling) with **zero port forwarding, zero router configuration, and end-to-end WireGuard encryption**.

```
  [Laptop / Mac on Coffee Shop Wi-Fi]
                 |
        (WireGuard Tunnel)
                 |
                 v
       Tailscale Private Mesh (100.x.y.z)
                 |
                 v
        (WireGuard Tunnel)
                 |
  [Windows Family PC at Home behind NAT / Firewall]
```

### Step 1: Install Tailscale on the Windows Endpoint

1. On the target Windows PC, download Tailscale from [tailscale.com/download/windows](https://tailscale.com/download/windows).
2. Run the installer and complete the setup.
3. Click the Tailscale icon in the Windows system tray and select **Log in...**.
4. Authenticate using your preferred identity provider (Google, Microsoft, Apple, or GitHub).
5. Once connected, right-click the Tailscale tray icon and copy the assigned **Tailscale IPv4 address** (this will start with `100.x.y.z`, e.g., `100.85.120.44`).

### Step 2: Install Tailscale on your macOS Admin Device

1. On your Mac (or administrative laptop), download Tailscale from the Mac App Store or [tailscale.com/download/mac](https://tailscale.com/download/mac).
2. Open Tailscale from the macOS menu bar and log in with the **exact same account** used on the Windows PC.
3. Both machines are now joined to your private, encrypted **Tailnet**.

### Step 3: Verify Point-to-Point Connectivity

Open Terminal on your Mac and verify connectivity using the Windows PC's `100.x.y.z` address:
```bash
ping 100.x.y.z
```
*(Replace `100.x.y.z` with the actual Tailscale IP of your Windows computer).*

### Step 4: Configure the Tailscale IP in AppShield Admin

1. Open `AppShield Admin.app` on your Mac.
2. Select your Windows endpoint from the fleet list (or click **Add Node** if adding for the first time).
3. In the endpoint configuration:
   - **Primary / LAN IP**: Set to your home network IP (e.g., `192.168.1.150`).
   - **Tailscale IP**: Set to the `100.x.y.z` address.
   - **Port**: `54120` (default).
   - **PSK**: The 32-character Pre-Shared Key.
4. Click **Save Changes**.

### Step 5: Test Remote Management

- Disconnect your Mac from your home Wi-Fi and connect to a mobile hotspot or guest network.
- The macOS Admin Dashboard will automatically detect that the local LAN IP is unreachable and seamlessly route management traffic through the secure Tailscale WireGuard tunnel!
- Real-time rule changes, live block notifications, and user quota adjustments will execute instantaneously.

---

## Windows Control Center Guide

When `AppShield-Setup.exe` is launched on an already-installed Windows machine by an Administrator, it opens the **AppShield Control Center**:

```
+----------------------------------------------------------------------------------+
| AppShield Endpoint Control Center                                       [-][x]   |
+----------------------------------------------------------------------------------+
| Status: SERVICE RUNNING (SYSTEM) | Version: 1.0.0 | UAC: Elevated Administrator   |
+----------------------------------------------------------------------------------+
| [Overview]  [Users & Path Jail]  [Blocked Apps]  [Live Logs]  [Safe Uninstaller] |
+----------------------------------------------------------------------------------+
|                                                                                  |
|  Blocked Applications:                                                           |
|  +--------------------+----------------+--------------------+---------+          |
|  | Process Name       | Rule Type      | Target User        | Status  |          |
|  +--------------------+----------------+--------------------+---------+          |
|  | discord.exe        | AlwaysBlock    | Protected Users    | Active  |          |
|  | robloxplayer.exe   | ScheduleBlock  | Protected Users    | Active  |          |
|  | steam.exe          | DailyQuota     | Protected Users    | Active  |          |
|  +--------------------+----------------+--------------------+---------+          |
|                                                                                  |
|  Add New Rule:                                                                   |
|  Process Name: [ steam.exe         ] [Browse .exe...]                           |
|  Target User:  [ All Protected Users (Managed)   v ]                             |
|  Rule Action:  [ Always Block                    v ]                             |
|                                                     [ + Add Blocking Rule ]      |
+----------------------------------------------------------------------------------+
```

### Control Center Capabilities:
1. **Overview & Connectivity**: Displays local IP, Tailscale IP, service status, and current Pre-Shared Key (PSK) for pairing with the macOS Dashboard.
2. **Users & Path Jail**: Lists all local Windows user accounts. Allows the Administrator to toggle:
   - **Managed Status**: Designates whether the user account is subject to AppShield rules.
   - **Path Jail (`BlockUserWritableDirectories`)**: Instantly locks down execution from `%USERPROFILE%\Downloads`, `%USERPROFILE%\Desktop`, `%APPDATA%`, and USB flash drives.
3. **Blocked Applications**: View, add, or remove blocked executables. Includes a **Browse .exe...** file picker to automatically extract the process name and original metadata from any installed program.
4. **Live Block Logs**: Real-time audit log showing timestamp, username, executable name, and blocking rationale.
5. **Safe Uninstaller**: Built-in uninstallation routine requiring Master Password verification to perform a complete, residue-free system cleanup.

---

## Enforcement Mechanisms

### 3-Layer Anti-Rename Detection

Standard users frequently attempt to bypass restrictions by renaming files (e.g. `robloxplayer.exe` -> `notepad.exe`). AppShield terminates processes if **ANY** of the following layers match an active rule:

```
[Target Process Launched]
           |
           +---> 1. Process Name Match (e.g., "discord.exe")
           |
           +---> 2. PE Header OriginalFilename (e.g., "Discord.exe" via FileVersionInfo)
           |
           +---> 3. Cached SHA-256 Hash Match (Cryptographic fingerprint)
           |
      [Match Found?]
         /      \
       YES       NO
       /          \
[Terminate Process] [Allow Process to Run]
```

### Path Jail (User-Writable Directory Blocking)

When Path Jail is enabled for a managed account, AppShield intercepts process creation and determines the execution directory. If the executable is located in any of the following paths, it is immediately terminated:
- `%USERPROFILE%\Downloads`
- `%USERPROFILE%\Desktop`
- `%APPDATA%` (Roaming)
- `%LOCALAPPDATA%\Temp`
- Removable media (USB flash drives, SD cards)

This prevents children from downloading portable gaming clients, browser bypasses, or proxy utilities.

### Session 0 Breakout & Native WinForms Prompts

Windows Services run in Session 0 and have no display context. When an application reaches its quota limit, AppShield safely bridges into the user's active session:
1. Uses `WTSGetActiveConsoleSessionId()` to identify the logged-in user.
2. Obtains the user's desktop token using `WTSQueryUserToken()`.
3. Duplicates the token via `DuplicateTokenEx()` with primary execution rights.
4. Spawns `AppShield.Prompt.exe` into desktop target `winsta0\default` using `CreateProcessAsUser()`.
5. Displays a topmost, modal 60-second countdown notification with an emergency offline Master Password bypass.

---

## Security & Tamper Resistance

- **Service Hardening**: The Windows Service is registered with `CanStop = false` and runs under `NT AUTHORITY\SYSTEM`. Standard users cannot stop the service via `net stop`, `sc stop`, or Task Manager.
- **NTFS Access Control Lists (ACLs)**: The installation folder (`C:\Program Files\AppShield`) and database directory (`C:\ProgramData\AppShield`) are restricted so that standard users cannot view, modify, or delete database files.
- **DPAPI Credential Protection**: The Master Password hash and PSK are encrypted at rest using the Windows Data Protection API (`ProtectedData.Protect` with `DataProtectionScope.LocalMachine`).
- **Mutual HTTPS & Replay Protection**: API requests between the macOS Dashboard and Windows Service use TLS 1.3/HTTPS, PSK authorization headers, and a 60-second timestamp drift check to prevent replay attacks.

---

## Safe Uninstallation & System Restore

AppShield can be uninstalled cleanly through four different methods:

### Method 1: Windows Settings (Standard Windows UI)
1. Open Windows **Settings** (`Win + I`).
2. Navigate to **Apps > Installed apps** (or **Add or Remove Programs**).
3. Find **AppShield** and click **Uninstall**.
4. Enter your **Master Password** in the uninstallation prompt to confirm.

### Method 2: Local Control Center
1. Open `AppShield-Setup.exe` from your Administrator Desktop or Start Menu.
2. Select the **Safe Uninstaller** tab.
3. Enter your Master Password and click **Perform Clean Uninstall**.

### Method 3: Remote Uninstallation from macOS Admin Dashboard
1. Open the endpoint in `AppShield Admin.app`.
2. Under **Danger Zone**, click **Uninstall Endpoint**.
3. Confirm with the Master Password. The Windows Service will spawn a detached cleanup script, terminate itself, unregister, and purge all files.

### Method 4: Silent CLI Uninstallation
Open an elevated PowerShell/Command Prompt window:
```powershell
"C:\Program Files\AppShield\AppShield-Setup.exe" --uninstall
```

**What the uninstaller cleans:**
- Stops and unregisters the `AppShieldService` Windows Service.
- Removes Windows Firewall rule `AppShield-Admin-Inbound`.
- Deletes Desktop and Start Menu shortcuts.
- Unregisters the Windows Programs & Features registry key.
- Purges `C:\Program Files\AppShield` and `C:\ProgramData\AppShield`.
- Leaves zero residual background processes.

---

## Building from Source

### Prerequisites
- macOS 13+ or Linux with [.NET 8.0 SDK](https://dotnet.microsoft.com/download/dotnet/8.0)
- Python 3.11+
- `zip` utility

### Build Command
Run the master cross-compilation script from the root directory:
```bash
./build-on-mac.sh
```

This compiles:
1. `AppShield.Service` -> `win-x64` self-contained single-file executable.
2. `AppShield.Prompt` -> `win-x64` self-contained single-file executable.
3. `AppShield.Installer` -> Packages binaries into `payload.zip` and builds `AppShield-Setup.exe`.
4. Assembles the deployment bundle in `dist/Windows-Client-Deploy/`.
5. Prepares the Python virtual environment and launcher for `AppShield Admin.app`.

---

## Privacy Disclosure

AppShield is designed with strict on-premises privacy:
- **Zero Cloud Services**: No telemetry, analytics, or process logs are ever transmitted to third-party cloud servers.
- **Local SQLite Storage**: Process logs and rules are stored strictly on the local machine.
- **Direct Peer-to-Peer Remote Access**: Remote administration through Tailscale routes encrypted traffic directly peer-to-peer using WireGuard.

---

## License

This project is licensed under the [MIT License](LICENSE).
