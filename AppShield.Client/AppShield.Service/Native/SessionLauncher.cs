using System.Diagnostics;
using System.Runtime.InteropServices;

namespace AppShield.Service.Native;

public static class SessionLauncher
{
    private const uint MAXIMUM_ALLOWED = 0x02000000;
    private const int SecurityIdentification = 2;
    private const int TokenPrimary = 1;
    private const uint CREATE_UNICODE_ENVIRONMENT = 0x00000400;

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct STARTUPINFO
    {
        public int cb;
        public string? lpReserved;
        public string? lpDesktop;
        public string? lpTitle;
        public int dwX;
        public int dwY;
        public int dwXSize;
        public int dwYSize;
        public int dwXCountChars;
        public int dwYCountChars;
        public int dwFillAttribute;
        public int dwFlags;
        public short wShowWindow;
        public short cbReserved2;
        public IntPtr lpReserved2;
        public IntPtr hStdInput;
        public IntPtr hStdOutput;
        public IntPtr hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct PROCESS_INFORMATION
    {
        public IntPtr hProcess;
        public IntPtr hThread;
        public int dwProcessId;
        public int dwThreadId;
    }

    [DllImport("wtsapi32.dll", SetLastError = true)]
    private static extern bool WTSQueryUserToken(uint SessionId, out IntPtr phToken);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint WTSGetActiveConsoleSessionId();

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool DuplicateTokenEx(
        IntPtr hExistingToken,
        uint dwDesiredAccess,
        IntPtr lpTokenAttributes,
        int ImpersonationLevel,
        int TokenType,
        out IntPtr phNewToken);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool CreateProcessAsUserW(
        IntPtr hToken,
        string? lpApplicationName,
        string? lpCommandLine,
        IntPtr lpProcessAttributes,
        IntPtr lpThreadAttributes,
        bool bInheritHandles,
        uint dwCreationFlags,
        IntPtr lpEnvironment,
        string? lpCurrentDirectory,
        ref STARTUPINFO lpStartupInfo,
        out PROCESS_INFORMATION lpProcessInformation);

    [DllImport("userenv.dll", SetLastError = true)]
    private static extern bool CreateEnvironmentBlock(out IntPtr lpEnvironment, IntPtr hToken, bool bInherit);

    [DllImport("userenv.dll", SetLastError = true)]
    private static extern bool DestroyEnvironmentBlock(IntPtr lpEnvironment);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr hObject);

    /// <summary>
    /// Spawns AppShield.Prompt.exe inside the active user's interactive Windows session (winsta0\default)
    /// breaking out of Windows Session 0 isolation.
    /// </summary>
    public static bool LaunchPromptInSession(int sessionId, string blockedAppName, string userSid, string reason)
    {
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            Console.WriteLine($"[Dev/Simulated Session Launch] Prompt spawned for '{blockedAppName}' (Session {sessionId})");
            return true;
        }

        uint targetSessionId = (uint)sessionId;
        if (targetSessionId == 0)
        {
            targetSessionId = WTSGetActiveConsoleSessionId();
            if (targetSessionId == 0xFFFFFFFF || targetSessionId == 0)
            {
                // No active interactive user session
                return false;
            }
        }

        IntPtr hUserToken = IntPtr.Zero;
        IntPtr hPrimaryToken = IntPtr.Zero;
        IntPtr lpEnvironment = IntPtr.Zero;

        try
        {
            if (!WTSQueryUserToken(targetSessionId, out hUserToken))
            {
                return false;
            }

            if (!DuplicateTokenEx(
                hUserToken,
                MAXIMUM_ALLOWED,
                IntPtr.Zero,
                SecurityIdentification,
                TokenPrimary,
                out hPrimaryToken))
            {
                return false;
            }

            // Target the default interactive desktop
            var si = new STARTUPINFO();
            si.cb = Marshal.SizeOf(si);
            si.lpDesktop = @"winsta0\default";

            CreateEnvironmentBlock(out lpEnvironment, hPrimaryToken, false);

            string promptExePath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "AppShield.Prompt.exe");
            if (!File.Exists(promptExePath))
            {
                promptExePath = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
                    "AppShield",
                    "AppShield.Prompt.exe");
            }

            string cmdLine = $"\"{promptExePath}\" --app \"{blockedAppName}\" --sid \"{userSid}\" --reason \"{reason}\"";

            bool result = CreateProcessAsUserW(
                hPrimaryToken,
                null,
                cmdLine,
                IntPtr.Zero,
                IntPtr.Zero,
                false,
                CREATE_UNICODE_ENVIRONMENT,
                lpEnvironment,
                null,
                ref si,
                out var pi);

            if (result)
            {
                CloseHandle(pi.hProcess);
                CloseHandle(pi.hThread);
            }

            return result;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[SessionLauncher] Failed to launch prompt: {ex.Message}");
            return false;
        }
        finally
        {
            if (lpEnvironment != IntPtr.Zero) DestroyEnvironmentBlock(lpEnvironment);
            if (hPrimaryToken != IntPtr.Zero) CloseHandle(hPrimaryToken);
            if (hUserToken != IntPtr.Zero) CloseHandle(hUserToken);
        }
    }
}
