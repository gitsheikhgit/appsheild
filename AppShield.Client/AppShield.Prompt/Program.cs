using System.Runtime.InteropServices;

namespace AppShield.Prompt;

internal static class Program
{
    [DllImport("kernel32.dll")]
    private static extern bool FreeConsole();

    [STAThread]
    private static void Main(string[] args)
    {
        // 1. Prevent Console Window flash when cross-compiled as WinExe from macOS
        try
        {
            FreeConsole();
        }
        catch
        {
        }

        // 2. Parse command line parameters
        string appName = "Application";
        string userSid = string.Empty;
        string reason = "Application restricted by administrator policy.";

        for (int i = 0; i < args.Length; i++)
        {
            if (args[i].Equals("--app", StringComparison.OrdinalIgnoreCase) && i + 1 < args.Length)
            {
                appName = args[++i];
            }
            else if (args[i].Equals("--sid", StringComparison.OrdinalIgnoreCase) && i + 1 < args.Length)
            {
                userSid = args[++i];
            }
            else if (args[i].Equals("--reason", StringComparison.OrdinalIgnoreCase) && i + 1 < args.Length)
            {
                reason = args[++i];
            }
        }

        // 3. Initialize WinForms
        ApplicationConfiguration.Initialize();
        Application.Run(new PromptForm(appName, userSid, reason));
    }
}
