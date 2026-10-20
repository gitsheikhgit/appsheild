# AppShield 🛡️
### Tamper-Resistant Windows Application Control & Multi-User Endpoint Fleet Management

**AppShield** is an enterprise-grade endpoint control system designed for Windows 10/11 (x64) shared/family computers. It combines low-level Windows kernel/service architecture (Session 0 isolation breakout, sub-millisecond native Win32 token lookup, 3-layer anti-rename process identification, daily runtime quotas, schedule blocks, path jails) with a modern macOS & Windows Admin Control Dashboard.

---

## Architecture Overview

```
                      +------------------------------------------+
                      |         macOS Admin Host (FastAPI)       |
                      |  - Fleet Manager & mDNS Discovery        |
                      |  - Automatic LAN / Tailscale Failover    |
                      |  - Tailwind + Alpine.js Dark-Mode UI     |
                      +------------------------------------------+
                                           |
                  HTTPS (Port 54120) with PSK + Timestamp Validation
                                           |
                                           v
       +------------------------------------------------------------------------+
       |                     Target Windows 10/11 Client                        |
       |                                                                        |
       |  [Session 0: Headless Service (NT AUTHORITY\SYSTEM)]                   |
       |  - CanStop = false (Tamper-Resistant)                                  |
       |  - Real-Time Hybrid Process Engine (WMI + 1500ms Polling)              |
       |  - Native Win32 Token Owner Lookup (OpenProcessToken)                  |
       |  - 3-Layer Anti-Rename Engine (Name + PE Header + Cached SHA-256)      |
       |  - Daily Quotas, Schedule Windows, Path Jail (%USERPROFILE%\Downloads) |
       |  - SQLite Database locked with NTFS ACLs & Windows DPAPI               |
       |  - Named Pipe Server (\\.\pipe\AppShieldOverridePipe)                  |
       |                                                                        |
       |  [Interactive User Session: GUI (winsta0\default)]                     |
       |  - Spawns via WTSQueryUserToken + CreateProcessAsUser                  |
       |  - AppShield.Prompt.exe (Topmost WinForms with 60s Countdown)          |
       |  - Emergency Offline Master Password Unlock                            |
       +------------------------------------------------------------------------+
```

---

## Key Features

1. **Session 0 Isolation Solution**:
   - Because Windows Services in Session 0 cannot interact directly with the user desktop, `AppShield.Service` uses native P/Invoke (`WTSQueryUserToken`, `DuplicateTokenEx`, `CreateProcessAsUser` targeting `winsta0\default`) to spawn `AppShield.Prompt.exe` on the interactive user desktop.

2. **3-Layer Anti-Rename Process Detection**:
   - Standard users frequently rename blocked executables (e.g. `discord.exe` -> `calc2.exe`). AppShield terminates processes if **ANY** of the following match:
     1. **Process/Executable Name** (e.g., `discord.exe`)
     2. **PE Header `OriginalFilename`** (e.g., `Discord.exe` extracted via `FileVersionInfo`)
     3. **SHA-256 File Hash** (cached by `FilePath + LastWriteTimeUtc` in memory)

3. **Sub-Millisecond Win32 Token Inspection**:
   - Avoids slow WMI `.GetOwner()` queries. Resolves process token user SID and Username directly via `advapi32.dll` (`OpenProcessToken`, `GetTokenInformation(TokenUser)`, `LookupAccountSidW`).

4. **Multi-User Selective Targeting**:
   - Only accounts configured as **Managed** are restricted. Administrator accounts and system processes (`NT AUTHORITY\SYSTEM`, `LOCAL SERVICE`) operate with zero restrictions.

5. **Path Jail (`BlockUserWritableDirectories`)**:
   - Prevents bypasses from portable executables launched from `%USERPROFILE%\Downloads`, `%USERPROFILE%\Desktop`, `%APPDATA%`, `%LOCALAPPDATA%\Temp`, or removable USB drives.

6. **Daily Time Quotas & Schedules**:
   - **AlwaysBlock**: 24/7 immediate process tree termination (`process.Kill(entireProcessTree: true)`).
   - **ScheduleBlock**: Restricted during specified time windows (e.g. `21:00` to `07:00`).
   - **DailyQuota**: Tracks cumulative active execution time in seconds; locks out the app once quota minutes are depleted.

7. **Tamper-Proof Remote Self-Destruct Uninstaller**:
   - No local entry in Windows "Apps & Features".
   - Verified remotely with PSK + Master Password, spawning a detached hidden cleanup script (`C:\Windows\Temp\appshield_purge.ps1`) that stops the service, deletes registration, removes firewall rules, and wipes all files.

---

## Quick Start: Build & Deploy

### Step 1: Build on macOS
From this directory, run:
```bash
./build-on-mac.sh
```
This will:
- Cross-compile `AppShield.Service` and `AppShield.Prompt` for `win-x64` self-contained single-file binaries.
- Assemble a clean, ready-to-copy installer folder at `dist/Windows-Client-Deploy/`.
- Configure the Python virtual environment (`AppShield.Admin/.venv`).
- Generate `run-admin-mac.command`.

### Step 2: Install on Target Windows Machine
1. Copy `dist/Windows-Client-Deploy/` to the target Windows 10/11 PC.
2. Open PowerShell as Administrator and run:
   ```powershell
   .\Install-AppShield.ps1
   ```
3. Enter your desired **Master Password**.
4. The installer outputs the target computer name, IP, and a 32-character Pre-Shared Key (PSK).

### Step 3: Launch Admin Control Dashboard on macOS
Double-click `run-admin-mac.command` or run:
```bash
cd AppShield.Admin
source .venv/bin/activate
python3 -m uvicorn main:app --host 127.0.0.1 --port 8080
```
Your browser will open to `http://127.0.0.1:8080`. Add the Windows machine using the IP and PSK, or use the 1-click **Scan Subnet (mDNS)** discovery tool!
