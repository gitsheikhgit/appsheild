using System.Windows.Forms;

namespace AppShield.Installer;

internal static class Program
{
    [STAThread]
    private static void Main(string[] args)
    {
        Application.EnableVisualStyles();
        Application.SetCompatibleTextRenderingDefault(false);

        // Check for Uninstall mode
        if (args.Any(a => a.Equals("--uninstall", StringComparison.OrdinalIgnoreCase) ||
                         a.Equals("/uninstall", StringComparison.OrdinalIgnoreCase)))
        {
            if (args.Any(a => a.Equals("--silent", StringComparison.OrdinalIgnoreCase) ||
                             a.Equals("/silent", StringComparison.OrdinalIgnoreCase)))
            {
                // Silent uninstall
                string pass = args.FirstOrDefault(a => a.StartsWith("--password=", StringComparison.OrdinalIgnoreCase))?["--password=".Length..] ?? "";
                InstallEngine.RunUninstall(pass, (pct, msg) => { }, out _);
                return;
            }

            Application.Run(new UninstallForm());
            return;
        }

        // Check for Silent Install mode
        if (args.Any(a => a.Equals("--silent", StringComparison.OrdinalIgnoreCase) ||
                         a.Equals("/silent", StringComparison.OrdinalIgnoreCase)))
        {
            string pass = args.FirstOrDefault(a => a.StartsWith("--password=", StringComparison.OrdinalIgnoreCase))?["--password=".Length..] ?? "AdminPassword123!";
            string psk = args.FirstOrDefault(a => a.StartsWith("--psk=", StringComparison.OrdinalIgnoreCase))?["--psk=".Length..] ?? InstallEngine.GeneratePsk();

            string installDir = args.FirstOrDefault(a => a.StartsWith("--dir=", StringComparison.OrdinalIgnoreCase))?["--dir=".Length..] ?? InstallEngine.GetDefaultInstallDirectory();
            InstallEngine.RunInstall(installDir, pass, psk, true, (pct, msg) => { });
            return;
        }

        // If already installed, launch the AppShield Control Center desktop interface!
        if (InstallEngine.IsInstalled())
        {
            if (!InstallEngine.IsCurrentProcessElevatedAdmin())
            {
                MessageBox.Show(
                    "AppShield Control Center is restricted to elevated Administrators only.\r\n\r\nPlease right-click the shortcut and choose 'Run as administrator'.",
                    "Access Denied — Administrator Only",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Warning);
                return;
            }

            InstallEngine.LaunchControlCenter();
            return;
        }

        // Standard First-Time GUI Install Mode
        Application.Run(new InstallerForm());
    }
}

