<#
.SYNOPSIS
    AppShield Target Machine Automated Installer (Run as Administrator)
.DESCRIPTION
    Installs AppShield.Service as a tamper-resistant Windows Service under NT AUTHORITY\SYSTEM,
    locks down NTFS ACLs on C:\ProgramData\AppShield, configures crash auto-restart recovery,
    sets up the Windows Defender Firewall rule for HTTPS port 54120, and initializes credentials.
#>

# Require Administrator Privileges
if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "ERROR: This installation script must be run as an Administrator! Right-click and select 'Run with PowerShell as Administrator'."
    Exit 1
}

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ServiceBinary = Join-Path $ScriptDir "AppShield.Service.exe"
$PromptBinary = Join-Path $ScriptDir "AppShield.Prompt.exe"

if (!(Test-Path $ServiceBinary) -or !(Test-Path $PromptBinary)) {
    Write-Error "Required binary files (AppShield.Service.exe, AppShield.Prompt.exe) were not found in '$ScriptDir'!"
    Exit 1
}

# Extract Version from binary
$AppVersion = (Get-Item $ServiceBinary).VersionInfo.ProductVersion
if ([string]::IsNullOrWhiteSpace($AppVersion)) {
    $AppVersion = (Get-Item $ServiceBinary).VersionInfo.FileVersion
}
if ([string]::IsNullOrWhiteSpace($AppVersion)) {
    $AppVersion = "1.0.0"
}

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "      AppShield Security Client Installer (v$AppVersion)  " -ForegroundColor Cyan
Write-Host "  Tamper-Resistant Application Control for Windows 10/11 " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host ""

# 1. Prompt for initial Master Password
Write-Host "Configure the Master Password for emergency offline unlocks and administrative authorization:" -ForegroundColor Yellow
$MasterPassword = ""
while ([string]::IsNullOrWhiteSpace($MasterPassword)) {
    $SecurePass = Read-Host -Prompt "Enter Master Password" -AsSecureString
    $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecurePass)
    $MasterPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
    [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)

    if ($MasterPassword.Length -lt 8) {
        Write-Warning "Password should be at least 8 characters long for security."
        $MasterPassword = ""
    }
}

# 2. Generate cryptographically random Pre-Shared Key (PSK)
$Rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
$PskBytes = New-Object byte[] 24
$Rng.GetBytes($PskBytes)
$GeneratedPsk = [System.BitConverter]::ToString($PskBytes).Replace("-", "").ToLowerInvariant()

Write-Host "`nGenerated Secure Pre-Shared Key (PSK):" -ForegroundColor Green
Write-Host "  $GeneratedPsk" -ForegroundColor Yellow -BackgroundColor Black
Write-Host ""

# 3. Create Target Directories
$InstallDir = "$env:ProgramFiles\AppShield"
$DataDir = "$env:ProgramData\AppShield"

Write-Host "[1/6] Preparing installation directories..." -ForegroundColor Gray
New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
New-Item -ItemType Directory -Path $DataDir -Force | Out-Null

# 4. Programmatically Enforce NTFS ACLs on Data Directory
Write-Host "[2/6] Enforcing NTFS Access Control Lists (ACLs) on $DataDir..." -ForegroundColor Gray
$Acl = Get-Acl -Path $DataDir
$Acl.SetAccessRuleProtection($true, $false) # Disable inheritance and remove existing ACEs

$SystemSid = New-Object System.Security.Principal.SecurityIdentifier([System.Security.Principal.WellKnownSidType]::LocalSystemSid, $null)
$AdminSid = New-Object System.Security.Principal.SecurityIdentifier([System.Security.Principal.WellKnownSidType]::BuiltinAdministratorsSid, $null)

$SystemRule = New-Object System.Security.AccessControl.FileSystemAccessRule($SystemSid, "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
$AdminRule = New-Object System.Security.AccessControl.FileSystemAccessRule($AdminSid, "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")

$Acl.AddAccessRule($SystemRule)
$Acl.AddAccessRule($AdminRule)
Set-Acl -Path $DataDir -AclObject $Acl

# 5. Copy Executable Binaries
Write-Host "[3/6] Copying AppShield binaries to $InstallDir..." -ForegroundColor Gray
Copy-Item -Path $ServiceBinary -Destination $InstallDir -Force
Copy-Item -Path $PromptBinary -Destination $InstallDir -Force

# 6. Stop and Clean Any Existing Service
$ServiceName = "AppShieldService"
if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) {
    Write-Host "Stopping and replacing existing $ServiceName..." -ForegroundColor Yellow
    Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
    & sc.exe delete $ServiceName | Out-Null
    Start-Sleep -Seconds 2
}

# 7. Register Windows Service under NT AUTHORITY\SYSTEM
Write-Host "[4/6] Registering $ServiceName under NT AUTHORITY\SYSTEM..." -ForegroundColor Gray
$BinPath = "`"$InstallDir\AppShield.Service.exe`""
New-Service -Name $ServiceName -DisplayName "AppShield Security Service (v$AppVersion)" `
    -BinaryPathName $BinPath -StartupType Automatic `
    -Description "Tamper-resistant application control and multi-user endpoint management service (v$AppVersion)." | Out-Null

# Configure Service Failure Recovery (Restart on crash: 1s / 1s / 1s)
& sc.exe failure $ServiceName reset= 0 actions= restart/1000/restart/1000/restart/1000 | Out-Null

# 8. Configure Windows Defender Firewall Rule
Write-Host "[5/6] Creating Windows Defender Firewall rule for HTTPS port 54120..." -ForegroundColor Gray
Remove-NetFirewallRule -DisplayName "AppShield_API_Port" -ErrorAction SilentlyContinue
New-NetFirewallRule -DisplayName "AppShield_API_Port" `
    -Direction Inbound -LocalPort 54120 -Protocol TCP -Action Allow `
    -Description "Permits incoming encrypted HTTPS management traffic from AppShield Admin Dashboard." | Out-Null

# 9. Start the Service
Write-Host "[6/6] Starting $ServiceName..." -ForegroundColor Gray
Start-Service -Name $ServiceName

# 10. Display Network Addresses for Admin Connection
$LanIps = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.InterfaceAlias -notlike "*Loopback*" -and $_.IPAddress -notlike "169.254*" }).IPAddress
$TailscaleIp = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.InterfaceAlias -like "*Tailscale*" -or $_.IPAddress -like "100.*" }).IPAddress

Write-Host ""
Write-Host "==========================================================" -ForegroundColor Green
Write-Host "      AppShield v$AppVersion Successfully Installed!      " -ForegroundColor Green
Write-Host "==========================================================" -ForegroundColor Green
Write-Host ""
Write-Host "Target Machine Summary:"
Write-Host "  Installed Version: " -NoNewline; Write-Host "v$AppVersion" -ForegroundColor Green
Write-Host "  Computer Name:     " -NoNewline; Write-Host $env:COMPUTERNAME -ForegroundColor Cyan
Write-Host "  LAN Subnet IP:     " -NoNewline; Write-Host ($LanIps -join ", ") -ForegroundColor Cyan
if ($TailscaleIp) {
    Write-Host "  Tailscale IP:      " -NoNewline; Write-Host ($TailscaleIp -join ", ") -ForegroundColor Cyan
}
Write-Host "  API Port:          " -NoNewline; Write-Host "54120 (HTTPS)" -ForegroundColor Cyan
Write-Host "  PSK:               " -NoNewline; Write-Host $GeneratedPsk -ForegroundColor Yellow -BackgroundColor Black
Write-Host ""
Write-Host "Note: Keep your Master Password safe for emergency overrides." -ForegroundColor Yellow
Write-Host ""
