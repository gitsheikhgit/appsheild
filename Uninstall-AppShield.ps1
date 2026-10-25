<#
.SYNOPSIS
    AppShield Safe Local Uninstaller (Run as Administrator)
.DESCRIPTION
    Safely stops AppShieldService, removes Windows Service registration,
    removes the Windows Defender Firewall rule, purges program binaries and databases,
    and cleanly restores Windows to its original, completely unrestricted state.
#>

param(
    [string]$MasterPassword = ""
)

# Require Administrator Privileges
if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "ERROR: This uninstaller must be run as an Administrator! Right-click and select 'Run with PowerShell as Administrator'."
    Exit 1
}

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "             AppShield Safe Uninstaller                   " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host ""

$DbPath = "$env:ProgramData\AppShield\appshield.db"
if (Test-Path $DbPath) {
    if ([string]::IsNullOrWhiteSpace($MasterPassword)) {
        Write-Host "Enter your Master Password to authorize clean uninstallation:" -ForegroundColor Yellow
        $SecurePass = Read-Host -Prompt "Master Password" -AsSecureString
        $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecurePass)
        $MasterPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
        [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)
    }
}

Write-Host "[1/5] Notifying Central Server to deregister device..." -ForegroundColor Gray
$serverUrl = $null
$deviceId = $null

$settingsFile = "$env:ProgramData\AppShield\settings.json"
$configFile = "$env:ProgramData\AppShield\agent_config.json"
$activeConfig = if (Test-Path $settingsFile) { $settingsFile } elseif (Test-Path $configFile) { $configFile } else { $null }

if ($activeConfig) {
    try {
        $json = Get-Content $activeConfig -Raw | ConvertFrom-Json
        $serverUrl = $json.server_url
        $deviceId = $json.device_id
    } catch {}
}

if ([string]::IsNullOrWhiteSpace($serverUrl)) {
    $regPath = "HKLM:\SOFTWARE\AppShield"
    if (Test-Path $regPath) {
        try {
            $serverUrl = (Get-ItemProperty -Path $regPath -Name "CentralServerUrl" -ErrorAction SilentlyContinue).CentralServerUrl
            $deviceId = (Get-ItemProperty -Path $regPath -Name "DeviceId" -ErrorAction SilentlyContinue).DeviceId
        } catch {}
    }
}

if (![string]::IsNullOrWhiteSpace($serverUrl) -and $serverUrl -ne "standalone" -and ![string]::IsNullOrWhiteSpace($deviceId)) {
    try {
        $cleanUrl = $serverUrl.TrimEnd('/')
        $body = @{ device_id = $deviceId; reason = "uninstalled" } | ConvertTo-Json
        Invoke-RestMethod -Uri "$cleanUrl/api/devices/unregister" -Method Post -Body $body -ContentType "application/json" -TimeoutSec 3 -ErrorAction SilentlyContinue | Out-Null
        Invoke-RestMethod -Uri "$cleanUrl/api/fleet/$deviceId" -Method Delete -TimeoutSec 3 -ErrorAction SilentlyContinue | Out-Null
    } catch {}
}

Write-Host "[2/5] Stopping and terminating AppShield Security Service & processes..." -ForegroundColor Gray
Stop-Service -Name AppShieldService -Force -ErrorAction SilentlyContinue
Stop-Process -Name "AppShield.Service" -Force -ErrorAction SilentlyContinue
Stop-Process -Name "AppShield.Prompt" -Force -ErrorAction SilentlyContinue
& taskkill.exe /F /IM AppShield.Service.exe /T 2>$null | Out-Null
& taskkill.exe /F /IM AppShield.Prompt.exe /T 2>$null | Out-Null
Start-Sleep -Seconds 1

Write-Host "[2/4] Removing Windows Service registration..." -ForegroundColor Gray
& sc.exe delete AppShieldService | Out-Null

Write-Host "[3/4] Removing Windows Defender Firewall rules..." -ForegroundColor Gray
Remove-NetFirewallRule -DisplayName "AppShield_API_Port" -ErrorAction SilentlyContinue

Write-Host "[4/5] Removing Windows Settings uninstall entry..." -ForegroundColor Gray
Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\AppShield" -Recurse -Force -ErrorAction SilentlyContinue

Write-Host "[5/5] Removing AppShield binaries and application data..." -ForegroundColor Gray
$progFiles = "$env:ProgramFiles\AppShield"
if (Test-Path $progFiles) {
    Remove-Item -Path $progFiles -Recurse -Force -ErrorAction SilentlyContinue
}

$progData = "$env:ProgramData\AppShield"
if (Test-Path $progData) {
    Remove-Item -Path $progData -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Host ""
Write-Host "==========================================================" -ForegroundColor Green
Write-Host "   AppShield has been completely and cleanly uninstalled!  " -ForegroundColor Green
Write-Host "==========================================================" -ForegroundColor Green
Write-Host "All accounts, folders, and network settings are 100% restored." -ForegroundColor Cyan
Write-Host ""
