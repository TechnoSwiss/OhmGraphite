using CsvHelper.Configuration.Attributes;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;

namespace OhmGraphite
{
    /// <summary>
    /// Exposes Windows interactive logon sessions (console + RDP).
    /// Totals:
    ///   - users.logged_in
    ///   - users.rdp_logged_in
    ///   - users.console_logged_in
    /// Per-user (username + domain):
    ///   - user.{username}.{domain}.logged_in
    ///   - user.{username}.{domain}.rdp_logged_in
    ///   - user.{username}.{domain}.console_logged_in
    /// </summary>
    public class SessionCollector : IGiveSensors
    {
        private const HardwareType HwType = HardwareType.OS;
        private const SensorType SensorKind = SensorType.UserSessions; // counts/flags

        public void Start() { }
        public void Dispose() { }

        public IEnumerable<ReportedValue> ReadAllSensors()
        {
            foreach (var v in Collect())
                yield return v;
        }

        private static IEnumerable<ReportedValue> Collect()
        {
            var sessions = WtsHelper.EnumerateActiveSessions();
            int total = 0;
            int rdp = 0;
            int console = 0;
            int disconnected = 0;
            int idx = 0;

            foreach (var s in sessions)
            {
                total++;
                if (s.IsRdp) rdp++; else console++;
                if (s.IsDisconnected) disconnected++;
            }

            yield return NewValue("/users/0/usersessions/0", "logged_in", total, 0);
            yield return NewValue("/users/0/usersessions/1", "rdp_logged_in", rdp, 1);
            yield return NewValue("/users/0/usersessions/2", "console_logged_in", console, 2);
            yield return NewValue("/users/0/usersessions/3", "disconnected_logged_in", disconnected, 3);

            // Determine the currently active user(s) for this host
            var activeUsers = sessions
                .Where(s => !string.IsNullOrEmpty(s.Username))
                .Select(s =>
                {
                    string domain = string.IsNullOrEmpty(s.Domain) ? "local" : s.Domain;
                    return $"{domain}\\{s.Username}";
                })
                .Distinct()
                .ToList();

            string whoValue = activeUsers.Count switch
            {
                0 => "Idle",
                1 => activeUsers[0],
                _ => string.Join(", ", activeUsers)
            };

            // Emit as a string metric
            yield return new ReportedValue("/users/0/usersessions/4", "who", 0, SensorKind, GetWindowsShortName(), HwType, whoValue, 0);
        }

        private static ReportedValue NewValue(string identifier, string sensor, float value, int sensorIndex)
        {
            return new ReportedValue(identifier, sensor, value, SensorKind, GetWindowsShortName(), HwType, "0", sensorIndex);
        }

        private static string SanitizeToken(string name)
        {
            if (string.IsNullOrWhiteSpace(name)) return null;
            var sb = new StringBuilder(name.Length);
            foreach (char c in name.Trim())
            {
                if (char.IsLetterOrDigit(c) || c == '-' || c == '_')
                    sb.Append(char.ToLowerInvariant(c));
                else if (char.IsWhiteSpace(c) || c == '\\' || c == '/' || c == '@' || c == '.')
                    sb.Append('_');
                else
                    sb.Append('_');
            }
            return sb.ToString();
        }

        private static string GetWindowsShortName()
        {
            Version v = Environment.OSVersion.Version;

            return v.Major switch
            {
                10 when v.Build >= 22000 => "Win11", // 22000+ is Windows 11
                10 => "Win10",
                6 when v.Minor == 3 => "Win8.1",
                6 when v.Minor == 2 => "Win8",
                6 when v.Minor == 1 => "Win7",
                _ => $"Unknown ({v})"
            };
        }

        private static class WtsHelper
        {
            public static IEnumerable<SessionInfo> EnumerateActiveSessions()
            {
                IntPtr pSessionInfo = IntPtr.Zero;
                int count = 0;
                try
                {
                    if (!WTSEnumerateSessions(IntPtr.Zero, 0, 1, out pSessionInfo, out count))
                        throw new Win32Exception(Marshal.GetLastWin32Error());

                    int dataSize = Marshal.SizeOf(typeof(WTS_SESSION_INFO));
                    for (int i = 0; i < count; i++)
                    {
                        IntPtr p = new IntPtr(pSessionInfo.ToInt64() + i * dataSize);
                        var si = Marshal.PtrToStructure<WTS_SESSION_INFO>(p);
                        if (si.State != WTS_CONNECTSTATE_CLASS.WTSActive &&
                            si.State != WTS_CONNECTSTATE_CLASS.WTSDisconnected)
                            continue;

                        string user = QueryString(si.SessionID, WTS_INFO_CLASS.WTSUserName);
                        string domain = QueryString(si.SessionID, WTS_INFO_CLASS.WTSDomainName);
                        string usernameFull = string.IsNullOrEmpty(domain) ? user : $"{domain}\\{user}";
                        if (string.IsNullOrEmpty(user))
                            continue;

                        ushort proto = QueryUShort(si.SessionID, WTS_INFO_CLASS.WTSClientProtocolType);
                        bool isRdp = (proto == 2); // 2 = RDP, 0 = console, 1 = other
                        bool isDisconnected = (si.State == WTS_CONNECTSTATE_CLASS.WTSDisconnected);

                        yield return new SessionInfo
                        {
                            SessionId = si.SessionID,
                            Username = user,
                            Domain = domain,
                            UsernameFull = usernameFull,
                            IsRdp = isRdp,
                            IsDisconnected = isDisconnected
                        };
                    }
                }
                finally
                {
                    if (pSessionInfo != IntPtr.Zero)
                        WTSFreeMemory(pSessionInfo);
                }
            }

            private static string QueryString(int sessionId, WTS_INFO_CLASS klass)
            {
                IntPtr buffer;
                int bytes;
                if (!WTSQuerySessionInformation(IntPtr.Zero, sessionId, klass, out buffer, out bytes) || buffer == IntPtr.Zero)
                    return null;
                try
                {
                    string s = Marshal.PtrToStringUni(buffer);
                    return s?.TrimEnd('\0');
                }
                finally
                {
                    WTSFreeMemory(buffer);
                }
            }

            private static ushort QueryUShort(int sessionId, WTS_INFO_CLASS klass)
            {
                IntPtr buffer;
                int bytes;
                if (!WTSQuerySessionInformation(IntPtr.Zero, sessionId, klass, out buffer, out bytes) || buffer == IntPtr.Zero)
                    return 0;
                try
                {
                    return (ushort)Marshal.ReadInt16(buffer);
                }
                finally
                {
                    WTSFreeMemory(buffer);
                }
            }

            [DllImport("wtsapi32.dll", SetLastError = true)]
            private static extern bool WTSEnumerateSessions(
                IntPtr hServer,
                int reserved,
                int version,
                out IntPtr ppSessionInfo,
                out int pCount);

            [DllImport("wtsapi32.dll")]
            private static extern void WTSFreeMemory(IntPtr pMemory);

            [DllImport("wtsapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
            private static extern bool WTSQuerySessionInformation(
                IntPtr hServer,
                int sessionId,
                WTS_INFO_CLASS wtsInfoClass,
                out IntPtr ppBuffer,
                out int pBytesReturned);

            private enum WTS_INFO_CLASS
            {
                WTSInitialProgram = 0,
                WTSApplicationName = 1,
                WTSWorkingDirectory = 2,
                WTSOEMId = 3,
                WTSSessionId = 4,
                WTSUserName = 5,
                WTSWinStationName = 6,
                WTSDomainName = 7,
                WTSConnectState = 8,
                WTSClientBuildNumber = 9,
                WTSClientName = 10,
                WTSClientDirectory = 11,
                WTSClientProductId = 12,
                WTSClientHardwareId = 13,
                WTSClientAddress = 14,
                WTSClientDisplay = 15,
                WTSClientProtocolType = 16
            }

            [StructLayout(LayoutKind.Sequential)]
            private struct WTS_SESSION_INFO
            {
                public int SessionID;
                public IntPtr pWinStationName;
                public WTS_CONNECTSTATE_CLASS State;
            }

            private enum WTS_CONNECTSTATE_CLASS
            {
                WTSActive,
                WTSConnected,
                WTSConnectQuery,
                WTSShadow,
                WTSDisconnected,
                WTSIdle,
                WTSListen,
                WTSReset,
                WTSDown,
                WTSInit
            }

            internal struct SessionInfo
            {
                public int SessionId;
                public string Username;
                public string Domain;
                public string UsernameFull;
                public bool IsRdp;
                public bool IsDisconnected;
            }
        }
    }
}