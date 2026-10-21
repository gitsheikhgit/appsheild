using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using Microsoft.Win32;
using AppShield.Shared.DTOs;
using AppShield.Shared.Models;
using AppShield.Shared.Security;

namespace AppShield.Service.Native;

public static class Win32ProcessHelper
{
    private const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;
    private const uint TOKEN_QUERY = 0x0008;

    [StructLayout(LayoutKind.Sequential)]
    private struct TOKEN_USER
    {
        public SID_AND_ATTRIBUTES User;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct SID_AND_ATTRIBUTES
    {
        public IntPtr Sid;
        public uint Attributes;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, int processId);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool GetTokenInformation(
        IntPtr TokenHandle,
        int TokenInformationClass,
        IntPtr TokenInformation,
        uint TokenInformationLength,
        out uint ReturnLength);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool LookupAccountSidW(
        string? lpSystemName,
        IntPtr lpSid,
        StringBuilder lpName,
        ref uint cchName,
        StringBuilder lpReferencedDomainName,
        ref uint cchReferencedDomainName,
        out int peUse);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(IntPtr hObject);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool ConvertSidToStringSidW(IntPtr pSid, out IntPtr ptrSid);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr LocalFree(IntPtr hMem);

    /// <summary>
    /// High-speed native Win32 Token lookup to resolve (Username, Domain, Sid) in sub-millisecond time.
    /// Returns ("SYSTEM", "NT AUTHORITY", "S-1-5-18") or similar for system processes.
    /// </summary>
    public static (string Username, string Domain, string Sid) GetProcessOwner(int pid)
    {
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            return (Environment.UserName, Environment.UserDomainName, "S-1-5-21-0000000000-0000000000-0000000000-1001");
        }

        IntPtr hProcess = IntPtr.Zero;
        IntPtr hToken = IntPtr.Zero;
        IntPtr pTokenUser = IntPtr.Zero;

        try
        {
            hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
            if (hProcess == IntPtr.Zero)
            {
                return (string.Empty, string.Empty, string.Empty);
            }

            if (!OpenProcessToken(hProcess, TOKEN_QUERY, out hToken))
            {
                return (string.Empty, string.Empty, string.Empty);
            }

            // Determine buffer size
            GetTokenInformation(hToken, 1 /* TokenUser */, IntPtr.Zero, 0, out uint tokenInfoLength);
            if (tokenInfoLength == 0)
            {
                return (string.Empty, string.Empty, string.Empty);
            }

            pTokenUser = Marshal.AllocHGlobal((int)tokenInfoLength);
            if (!GetTokenInformation(hToken, 1, pTokenUser, tokenInfoLength, out _))
            {
                return (string.Empty, string.Empty, string.Empty);
            }

            var tokenUser = Marshal.PtrToStructure<TOKEN_USER>(pTokenUser);
            IntPtr pSid = tokenUser.User.Sid;

            // Convert SID to string representation
            string sidString = string.Empty;
            if (ConvertSidToStringSidW(pSid, out IntPtr pSidStr))
            {
                sidString = Marshal.PtrToStringUni(pSidStr) ?? string.Empty;
                LocalFree(pSidStr);
            }

            // Lookup Account Name and Domain
            uint nameCap = 256;
            uint domainCap = 256;
            var name = new StringBuilder((int)nameCap);
            var domain = new StringBuilder((int)domainCap);

            if (LookupAccountSidW(null, pSid, name, ref nameCap, domain, ref domainCap, out _))
            {
                return (name.ToString(), domain.ToString(), sidString);
            }

            return (sidString, string.Empty, sidString);
        }
        catch
        {
            return (string.Empty, string.Empty, string.Empty);
        }
        finally
        {
            if (pTokenUser != IntPtr.Zero) Marshal.FreeHGlobal(pTokenUser);
            if (hToken != IntPtr.Zero) CloseHandle(hToken);
            if (hProcess != IntPtr.Zero) CloseHandle(hProcess);
        }
    }

    /// <summary>
    /// Reads PE header OriginalFilename via FileVersionInfo.
    /// </summary>
    public static string GetOriginalFilename(string exePath)
    {
        if (string.IsNullOrWhiteSpace(exePath) || !File.Exists(exePath))
            return string.Empty;

        try
        {
            var versionInfo = FileVersionInfo.GetVersionInfo(exePath);
            return versionInfo.OriginalFilename?.Trim() ?? string.Empty;
        }
        catch
        {
            return string.Empty;
        }
    }

    /// <summary>
    /// Detects if an executable was launched from a user-writable directory
    /// (%USERPROFILE%\Downloads, Desktop, %APPDATA%, %LOCALAPPDATA%\Temp, or Removable Drives).
    /// </summary>
    public static bool IsUserWritablePath(string exePath)
    {
        if (string.IsNullOrWhiteSpace(exePath))
            return false;

        try
        {
            string fullPath = Path.GetFullPath(exePath);

            // Check removable drives
            string? root = Path.GetPathRoot(fullPath);
            if (!string.IsNullOrEmpty(root))
            {
                var drive = new DriveInfo(root);
                if (drive.DriveType == DriveType.Removable)
                    return true;
            }

            string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            string appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
            string localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            string tempDir = Path.GetTempPath();

            string downloads = Path.Combine(userProfile, "Downloads");
            string desktop = Environment.GetFolderPath(Environment.SpecialFolder.Desktop);

            if (IsSubdirectoryOf(fullPath, downloads) ||
                IsSubdirectoryOf(fullPath, desktop) ||
                IsSubdirectoryOf(fullPath, appData) ||
                IsSubdirectoryOf(fullPath, tempDir) ||
                IsSubdirectoryOf(fullPath, localAppData))
            {
                return true;
            }

            return false;
        }
        catch
        {
            return false;
        }
    }

    private static bool IsSubdirectoryOf(string filePath, string parentDir)
    {
        if (string.IsNullOrWhiteSpace(parentDir) || string.IsNullOrWhiteSpace(filePath))
            return false;

        string normalizedParent = Path.GetFullPath(parentDir).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar) + Path.DirectorySeparatorChar;
        string normalizedFile = Path.GetFullPath(filePath);

        return normalizedFile.StartsWith(normalizedParent, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Safely terminates an entire process tree.
    /// </summary>
    public static bool KillProcessTree(int pid)
    {
        try
        {
            using var proc = Process.GetProcessById(pid);
            proc.Kill(entireProcessTree: true);
            return true;
        }
        catch (ArgumentException)
        {
            // Process already exited
            return true;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Enumerates all local Windows user accounts.
    /// </summary>
    public static List<UserAccount> EnumerateLocalUsers()
    {
        var users = new List<UserAccount>();

        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            // Mock fallback for non-Windows dev host
            users.Add(new UserAccount
            {
                Username = Environment.UserName,
                Domain = Environment.UserDomainName,
                Sid = "S-1-5-21-3623811015-3361044348-30300820-1001",
                IsAdmin = true,
                IsManaged = false,
                BlockUserWritableDirectories = false,
                LastSeenUtc = DateTime.UtcNow
            });
            users.Add(new UserAccount
            {
                Username = "ChildUser",
                Domain = Environment.MachineName,
                Sid = "S-1-5-21-3623811015-3361044348-30300820-1002",
                IsAdmin = false,
                IsManaged = true,
                BlockUserWritableDirectories = true,
                LastSeenUtc = DateTime.UtcNow
            });
            return users;
        }

        try
        {
            // Query local accounts via System.DirectoryServices.AccountManagement or WMI
            // Using WMI Win32_UserAccount for reliable, universal Windows support
            using var searcher = new System.Management.ManagementObjectSearcher("SELECT * FROM Win32_UserAccount WHERE LocalAccount = True");
            using var collection = searcher.Get();

            foreach (System.Management.ManagementObject obj in collection)
            {
                string name = obj["Name"]?.ToString() ?? string.Empty;
                string domain = obj["Domain"]?.ToString() ?? string.Empty;
                string sid = obj["SID"]?.ToString() ?? string.Empty;
                bool disabled = (bool)(obj["Disabled"] ?? false);

                if (disabled || string.IsNullOrEmpty(sid))
                    continue;

                // Check admin status via local group check
                bool isAdmin = false;
                try
                {
                    var sidObj = new SecurityIdentifier(sid);
                    var adminGroupSid = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
                    // Check if current user is in Administrators
                    // Or query local group membership
                    isAdmin = IsUserInAdminGroup(name);
                }
                catch
                {
                    isAdmin = false;
                }

                users.Add(new UserAccount
                {
                    Username = name,
                    Domain = domain,
                    Sid = sid,
                    IsAdmin = isAdmin,
                    IsManaged = false,
                    BlockUserWritableDirectories = false,
                    LastSeenUtc = DateTime.UtcNow
                });
            }
        }
        catch
        {
            // Fallback: add current Windows identity
            try
            {
                var identity = WindowsIdentity.GetCurrent();
                users.Add(new UserAccount
                {
                    Username = identity.Name.Split('\\').Last(),
                    Domain = identity.Name.Contains('\\') ? identity.Name.Split('\\').First() : Environment.MachineName,
                    Sid = identity.User?.Value ?? string.Empty,
                    IsAdmin = identity.Owner?.Equals(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null)) ?? false,
                    IsManaged = false,
                    BlockUserWritableDirectories = false,
                    LastSeenUtc = DateTime.UtcNow
                });
            }
            catch
            {
            }
        }

        return users;
    }

    private static bool IsUserInAdminGroup(string username)
    {
        try
        {
            using var searcher = new System.Management.ManagementObjectSearcher(
                $"SELECT * FROM Win32_GroupUser WHERE GroupComponent = \"Win32_Group.Domain='{Environment.MachineName}',Name='Administrators'\"");
            using var collection = searcher.Get();

            foreach (System.Management.ManagementObject obj in collection)
            {
                string part = obj["PartComponent"]?.ToString() ?? string.Empty;
                if (part.Contains($"Name=\"{username}\"", StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }
            }
        }
        catch
        {
        }
        return false;
    }

    public static List<InstalledAppDto> EnumerateInstalledApplications()
    {
        var apps = new Dictionary<string, InstalledAppDto>(StringComparer.OrdinalIgnoreCase);

        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            return apps.Values.ToList();
        }

        try
        {
            var registryViews = new[] { RegistryView.Registry64, RegistryView.Registry32 };
            var hives = new[] { RegistryHive.LocalMachine, RegistryHive.CurrentUser };

            foreach (var hive in hives)
            {
                foreach (var view in registryViews)
                {
                    try
                    {
                        using var baseKey = RegistryKey.OpenBaseKey(hive, view);
                        using var uninstallKey = baseKey.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall");
                        if (uninstallKey == null) continue;

                        foreach (var subKeyName in uninstallKey.GetSubKeyNames())
                        {
                            try
                            {
                                using var subKey = uninstallKey.OpenSubKey(subKeyName);
                                if (subKey == null) continue;

                                string displayName = subKey.GetValue("DisplayName")?.ToString()?.Trim() ?? string.Empty;
                                if (string.IsNullOrWhiteSpace(displayName)) continue;

                                var isSystemComponent = subKey.GetValue("SystemComponent");
                                if (isSystemComponent is int sys && sys == 1) continue;

                                var parentKeyName = subKey.GetValue("ParentKeyName");
                                if (parentKeyName != null) continue;

                                string publisher = subKey.GetValue("Publisher")?.ToString()?.Trim() ?? string.Empty;
                                string version = subKey.GetValue("DisplayVersion")?.ToString()?.Trim() ?? string.Empty;
                                string installLocation = subKey.GetValue("InstallLocation")?.ToString()?.Trim() ?? string.Empty;
                                string displayIcon = subKey.GetValue("DisplayIcon")?.ToString()?.Trim() ?? string.Empty;

                                string exeName = string.Empty;
                                if (!string.IsNullOrEmpty(displayIcon))
                                {
                                    string cleanIcon = displayIcon.Split(',')[0].Trim('"', ' ');
                                    if (cleanIcon.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
                                    {
                                        exeName = Path.GetFileName(cleanIcon);
                                    }
                                }

                                if (string.IsNullOrEmpty(exeName) && !string.IsNullOrEmpty(installLocation) && Directory.Exists(installLocation))
                                {
                                    try
                                    {
                                        var mainExe = Directory.GetFiles(installLocation, "*.exe", SearchOption.TopDirectoryOnly)
                                            .OrderByDescending(f => new FileInfo(f).Length)
                                            .FirstOrDefault();
                                        if (mainExe != null)
                                        {
                                            exeName = Path.GetFileName(mainExe);
                                        }
                                    }
                                    catch { }
                                }

                                if (!apps.ContainsKey(displayName))
                                {
                                    apps[displayName] = new InstalledAppDto
                                    {
                                        DisplayName = displayName,
                                        DisplayVersion = version,
                                        Publisher = publisher,
                                        ExeName = exeName,
                                        InstallPath = installLocation
                                    };
                                }
                            }
                            catch { }
                        }
                    }
                    catch { }
                }
            }
        }
        catch { }

        return apps.Values.OrderBy(a => a.DisplayName).ToList();
    }
}
