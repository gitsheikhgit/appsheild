using System.Diagnostics;
using System.Runtime.InteropServices;
using AppShield.Service.Storage;
using AppShield.Shared.Security;

namespace AppShield.Service.Maintenance;

public static class UninstallRoutine
{
    public static bool ExecuteRemoteUninstall(StorageManager storage, string masterPassword, Action allowStopAction)
    {
        // 1. Verify Master Password
        string storedHash = storage.GetSetting("MasterPasswordHash");
        if (!CryptoHelper.VerifyPassword(masterPassword, storedHash))
        {
            return false;
        }

        // 2. Flip internal allowStop flag so Windows Service manager can stop it
        allowStopAction();

        // 3. Write self-deleting purge script
        string tempDir = RuntimeInformation.IsOSPlatform(OSPlatform.Windows)
            ? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Temp")
            : Path.GetTempPath();

        string scriptPath = Path.Combine(tempDir, "appshield_purge.ps1");

        string purgeScript = @"
Start-Sleep -Seconds 3

# Stop Windows Service
try {
    Stop-Service -Name AppShieldService -Force -ErrorAction SilentlyContinue
} catch {}

# Delete Windows Service registration
try {
    & sc.exe delete AppShieldService
} catch {}

# Remove Windows Firewall Rule
try {
    Remove-NetFirewallRule -DisplayName ""AppShield_API_Port"" -ErrorAction SilentlyContinue
} catch {}

# Remove Windows Settings Uninstall Registration
try {
    Remove-Item -Path ""HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\AppShield"" -Recurse -Force -ErrorAction SilentlyContinue
} catch {}

# Force delete Program Files
$progFiles = ""$env:ProgramFiles\AppShield""
if (Test-Path $progFiles) {
    try { Remove-Item -Path $progFiles -Recurse -Force -ErrorAction SilentlyContinue } catch {}
}

# Force delete ProgramData
$progData = ""$env:ProgramData\AppShield""
if (Test-Path $progData) {
    try { Remove-Item -Path $progData -Recurse -Force -ErrorAction SilentlyContinue } catch {}
}

# Delete self
try {
    Remove-Item -Path $MyInvocation.MyCommand.Path -Force -ErrorAction SilentlyContinue
} catch {}
";

        try
        {
            File.WriteAllText(scriptPath, purgeScript);

            // 4. Launch detached hidden process
            var psi = new ProcessStartInfo
            {
                FileName = "powershell.exe",
                Arguments = $"-ExecutionPolicy Bypass -NoProfile -WindowStyle Hidden -File \"{scriptPath}\"",
                UseShellExecute = true,
                CreateNoWindow = true,
                WindowStyle = ProcessWindowStyle.Hidden
            };

            Process.Start(psi);
            return true;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[UninstallRoutine] Error launching purge: {ex.Message}");
            return false;
        }
    }
}
