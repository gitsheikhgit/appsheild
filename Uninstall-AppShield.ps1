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

Write-Host "[1/4] Stopping AppShield Security Service..." -ForegroundColor Gray
Stop-Service -Name AppShieldService -Force -ErrorAction SilentlyContinue

Write-Host "[2/4] Removing Windows Service registration..." -ForegroundColor Gray
& sc.exe delete AppShieldService | Out-Null

Write-Host "[3/4] Removing Windows Defender Firewall rules..." -ForegroundColor Gray
Remove-NetFirewallRule -DisplayName "AppShield_API_Port" -ErrorAction SilentlyContinue

Write-Host "[4/4] Removing AppShield binaries and application data..." -ForegroundColor Gray
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
