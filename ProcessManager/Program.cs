/** Name: ProcessManager
 * Author: TheWover
 * Description: Displays useful information about processes running on a local or remote machine.
 * 
 * Last Modified: 04/13/2018
 * 
 */

using System;
using System.Linq;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.ComponentModel;
using System.Security.Principal;

namespace ProcessManager
{

    class Program
    {
        private struct Arguments
        {
            public string processname;
            public string machinename;
            public bool help;
        }

        static void Main(string[] args)
        {
            //Parse command-line arguments
            Arguments arguments = ParseArgs(args);

            if (args.Length > 0)
            {
                if (arguments.help == true)
                {
                    PrintUsage();
                    Environment.Exit(0);
                }

                Console.WriteLine("{0,-30} {1,-10} {2,-10} {3,-10} {4,-10} {5,-10} {6,-10} {7}", "Process Name", "PID", "PPID", "Arch", "Managed", "Session", "Integrity", "User");

                //If the user specifed that a different machine should be used, then parse for the machine name and run the command.
                if (arguments.machinename != null)
                {
                    try
                    {
                        if (arguments.processname != null)
                            
                            //Enumerate the processes
                            DescribeProcesses(Process.GetProcessesByName(arguments.processname, arguments.machinename));
                        else

                            //Enumerate the processes
                            DescribeProcesses(Process.GetProcesses(arguments.machinename));
                    }
                    catch
                    {
                        Console.WriteLine("Error: Invalid machine name.");

                        Environment.Exit(1);
                    }
                }
                else
                {
                    if (arguments.processname != null)
                        //Enumerate the processes
                        DescribeProcesses(Process.GetProcessesByName(arguments.processname));
                    else
                        //Enumerate the processes
                        DescribeProcesses(Process.GetProcesses());
                }
                
            }
            else
            {
                Console.WriteLine("{0,-30} {1,-10} {2,-10} {3,-10} {4,-10} {5,-10} {6,-10} {7}", "Process Name", "PID", "PPID", "Arch", "Managed", "Session", "Integrity" , "User");

                DescribeProcesses(Process.GetProcesses());
            }
        }

        private static Arguments ParseArgs(string[] args)
        {
            Arguments arguments = new Arguments();
            arguments.help = false;
            arguments.machinename = null;
            arguments.processname = null;

            if (args.Length > 0)
            {
                if (args.Contains("--help") || args.Contains("-h"))
                {
                    arguments.help = true;
                }
            }

            //Filter by process name
            if (args.Contains("--name") && args.Length >= 2)
            {
                //The number of the command line argument that specifies the process name
                int nameindex = new System.Collections.Generic.List<string>(args).IndexOf("--name") + 1;

                arguments.processname = args[nameindex];
            }

            //If the user specifed that a different machine should be used, then parse for the machine name and run the command.
            if (args.Contains("--machine") && args.Length >= 2)
            {
                try
                {
                    //The number of the command line argument that specifies the machine name
                    int machineindex = new System.Collections.Generic.List<string>(args).IndexOf("--machine") + 1;

                    arguments.machinename = args[machineindex];
                }
                catch
                {
                    Console.WriteLine("Error: Invalid machine name.");

                    Environment.Exit(1);
                }

            }

            return arguments;
        }

        private static void PrintUsage()
        {
            Console.WriteLine();
            Console.WriteLine("| Process Manager [v0.2]");
            Console.WriteLine("| Copyright (c) 2019 TheWover");
            Console.WriteLine();

            Console.WriteLine("Usage: ProcessManager.exe [machine]");
            Console.WriteLine();

            Console.WriteLine("{0,-5} {1,-20} {2}", "", "-h, --help", "Display this help menu.");
            Console.WriteLine("{0,-5} {1,-20} {2}", "", "--machine", "Specify a machine to query. Machine name or IP Address may be used.");
            Console.WriteLine("{0,-5} {1,-20} {2}", "", "--name", "Filter by a process name.");
            Console.WriteLine();

            Console.WriteLine("Examples:");
            Console.WriteLine();

            Console.WriteLine("ProcessManager.exe");
            Console.WriteLine("ProcessManager.exe --name svchost");
            Console.WriteLine("ProcessManager.exe --machine workstation2");
            Console.WriteLine("ProcessManager.exe --machine 10.30.134.13");
            Console.WriteLine();
        }        

        private static void DescribeProcesses(Process[] processes)
        {
            
            //Sort in ascending order by PID
            processes = processes.OrderBy(p => p.Id).ToArray();

            foreach (Process process in processes)
            {
                //Get the PID
                ProcessDetails details = new ProcessDetails();
                details.name = process.ProcessName;
                details.pid = process.Id;

                try
                { 
                    //Get the PPID
                    Process parent = ParentProcessUtilities.GetParentProcess(process.Id);
                    if (parent != null)
                        details.ppid = parent.Id;
                    else
                        details.ppid = -1;
                }
                //Parent is no longer running
                catch (InvalidOperationException)
                {
                    details.ppid = -1;
                }


            //Check the architecture
            try
                {
                    if (ProcessInspector.IsWow64Process(process))
                        details.arch = "x86";
                    else
                        details.arch = "x64";
                }
                catch
                {
                    details.arch = "*";
                }

                try
                {
                    //Determine whether or not the process is managed (has the CLR loaded).
                    details.managed = ProcessInspector.IsCLRLoaded(process);
                }
                //Process is no longer running
                catch (InvalidOperationException)
                {
                    details.managed = false;
                }


                try
                {
                    //Gets the Session of the Process
                    details.session = process.SessionId;
                }
                //Process is no longer running
                catch (InvalidOperationException)
                {
                    details.session = -1;
                }


                try
                {
                    //Gets the Integrity Level of the process
                    details.integrity = TokenInspector.GetIntegrityLevel(process);
                }
                //Process is no longer running
                catch (InvalidOperationException)
                {
                    details.integrity = TokenInspector.IntegrityLevel.Unknown;
                }


                try
                {
                    //Gets the User of the Process
                    details.user = ProcessInspector.GetProcessUser(process);
                }
                //Process is no longer running
                catch (InvalidOperationException)
                {
                    details.user = "";
                }

                Console.WriteLine("{0,-30} {1,-10} {2,-10} {3,-10} {4,-10} {5,-10} {6,-10} {7}", details.name, details.pid, details.ppid, details.arch, details.managed, details.session, details.integrity, details.user);
            }
        }
    }

    public struct ProcessDetails
    {
        public string name;
        public int pid;
        public int ppid;
        public string arch;
        public bool managed;
        public int session;
        public TokenInspector.IntegrityLevel integrity;
        public string user;
    }

    public static class ProcessInspector
    {

        [System.Runtime.InteropServices.DllImport("kernel32.dll")]
        public static extern bool IsWow64Process(System.IntPtr hProcess, out bool lpSystemInfo);

        [DllImport("ntdll.dll")]
        private static extern int NtQueryInformationProcess(IntPtr processHandle, int processInformationClass, ref ParentProcessUtilities processInformation, int processInformationLength, out int returnLength);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);
        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CloseHandle(IntPtr hObject);

        /// <summary>
        /// Gets the parent process of a specified process.
        /// </summary>
        /// <returns>A Process object representing the parent.</returns>
        public static Process GetParentProcess(Process process)
        {
            return ParentProcessUtilities.GetParentProcess(process.Id);
        }

        /// <summary>
        /// Gets the parent process of a specified process.
        /// </summary>
        /// <returns>A Process object representing the parent.</returns>
        public static Process GetParentProcess()
        {
            return GetParentProcess(Process.GetCurrentProcess());
        }

        /// <summary>
        /// Checks whether the process is 64-bit.
        /// </summary>
        /// <returns>Returns true if process is 64-bit, and false if process is 32-bit.</returns>
        public static bool IsWow64Process(Process process)
        {
            bool retVal = false;
            IsWow64Process(process.Handle, out retVal);
            return retVal;
        }

        /// <summary>
        /// Checks whether the process is 64-bit.
        /// </summary>
        /// <returns>Returns false if process is 64-bit, and true if process is 32-bit. Refer to MSDN for further details.</returns>
        public static bool IsWow64Process()
        {
            bool retVal = false;
            IsWow64Process(Process.GetCurrentProcess().Handle, out retVal);
            return retVal;
        }

        /// <summary>
        /// Checks if the CLR has been loaded into the specified process by 
        /// looking for loaded modules that contain "mscor" in the name.
        /// </summary>
        /// <param name="process">The process to check.</param>
        /// <returns>True if the CLR has been loaded. False if it has not.</returns>
        public static bool IsCLRLoaded(Process process)
        {
            try
            {
                var modules = from module in process.Modules.OfType<ProcessModule>()
                              select module;

                return modules.Any(pm => pm.ModuleName.Contains("mscor"));
            }
            //Access was denied
            catch (Win32Exception)
            {
                return false;
            }
            //Process has already exited
            catch (InvalidOperationException)
            {
                return false;
            }
            
        }

        /// <summary>
        /// Gets the owner of a process.
        /// 
        /// https://stackoverflow.com/questions/777548/how-do-i-determine-the-owner-of-a-process-in-c
        /// </summary>
        /// <param name="process">The process to inspect.</param>
        /// <returns>The name of the user, or null if it could not be read.</returns>
        public static string GetProcessUser(Process process)
        {
            IntPtr processHandle = IntPtr.Zero;
            try
            {
                OpenProcessToken(process.Handle, 8, out processHandle);
                WindowsIdentity wi = new WindowsIdentity(processHandle);
                return wi.Name;
            }
            catch
            {
                return null;
            }
            finally
            {
                if (processHandle != IntPtr.Zero)
                {
                    CloseHandle(processHandle);
                }
            }
        }

    }//end class

    /// <summary>
    /// A utility class to determine a process parent.
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    public struct ParentProcessUtilities
    {
        // These members must match PROCESS_BASIC_INFORMATION
        internal IntPtr Reserved1;
        internal IntPtr PebBaseAddress;
        internal IntPtr Reserved2_0;
        internal IntPtr Reserved2_1;
        internal IntPtr UniqueProcessId;
        internal IntPtr InheritedFromUniqueProcessId;

        [DllImport("ntdll.dll")]
        private static extern int NtQueryInformationProcess(IntPtr processHandle, int processInformationClass, ref ParentProcessUtilities processInformation, int processInformationLength, out int returnLength);

        /// <summary>
        /// Gets the parent process of the current process.
        /// </summary>
        /// <returns>An instance of the Process class.</returns>
        public static Process GetParentProcess()
        {
            return GetParentProcess(Process.GetCurrentProcess().Handle);
        }

        /// <summary>
        /// Gets the parent process of specified process.
        /// </summary>
        /// <param name="id">The process id.</param>
        /// <returns>An instance of the Process class.</returns>
        public static Process GetParentProcess(int id)
        {
            try
            {
                Process process = Process.GetProcessById(id);

                GetParentProcess(process.Handle);

                return GetParentProcess(process.Handle);
            }
            //Access was denied, or 
            catch 
            {
                return null;
            }
        }

        /// <summary>
        /// Gets the parent process of a specified process.
        /// </summary>
        /// <param name="handle">The process handle.</param>
        /// <returns>An instance of the Process class.</returns>
        public static Process GetParentProcess(IntPtr handle)
        {
            ParentProcessUtilities pbi = new ParentProcessUtilities();
            int returnLength;
            int status = NtQueryInformationProcess(handle, 0, ref pbi, Marshal.SizeOf(pbi), out returnLength);
            if (status != 0)
                throw new Win32Exception(status);

            try
            {
                return Process.GetProcessById(pbi.InheritedFromUniqueProcessId.ToInt32());
            }
            catch (ArgumentException)
            {
                // not found
                return null;
            }
        }
    }

    /// <summary>
    /// Inspects the tokens of an arbitrary Process and reports useful information.
    /// 
    /// This class is almost entirely copied from the example provided by pinvoke.net:
    /// http://pinvoke.net/default.aspx/Constants/SECURITY_MANDATORY.html
    /// </summary>
    public class TokenInspector
    {
        [DllImport("advapi32.dll", SetLastError = true)]
        static extern IntPtr GetSidSubAuthority(IntPtr sid, UInt32 subAuthorityIndex);

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern IntPtr GetSidSubAuthorityCount(IntPtr sid);

        // winnt.h, Windows SDK v6.1
        const int SECURITY_MANDATORY_UNTRUSTED_RID = (0x00000000);
        const int SECURITY_MANDATORY_LOW_RID = (0x00001000);
        const int SECURITY_MANDATORY_MEDIUM_RID = (0x00002000);
        const int SECURITY_MANDATORY_HIGH_RID = (0x00003000);
        const int SECURITY_MANDATORY_SYSTEM_RID = (0x00004000);
        const int SECURITY_MANDATORY_PROTECTED_PROCESS_RID = (0x00005000);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool OpenProcessToken(
            IntPtr ProcessHandle,
            UInt32 DesiredAccess,
            out IntPtr TokenHandle
            );

        const UInt32 TOKEN_QUERY = 0x0008;

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool GetTokenInformation(
            IntPtr TokenHandle,
            TOKEN_INFORMATION_CLASS TokenInformationClass,
            IntPtr TokenInformation,
            uint TokenInformationLength,
            out uint ReturnLength
            );

        enum TOKEN_INFORMATION_CLASS
        {
            TokenUser = 1, TokenGroups, TokenPrivileges, TokenOwner, TokenPrimaryGroup, TokenDefaultDacl, TokenSource, TokenType, TokenImpersonationLevel, TokenStatistics, TokenRestrictedSids, TokenSessionId, TokenGroupsAndPrivileges, TokenSessionReference, TokenSandBoxInert, TokenAuditPolicy, TokenOrigin, TokenElevationType, TokenLinkedToken, TokenElevation, TokenHasRestrictions, TokenAccessInformation, TokenVirtualizationAllowed, TokenVirtualizationEnabled,

            /// <summary>
            /// The buffer receives a TOKEN_MANDATORY_LABEL structure that specifies the token's integrity level. 
            /// </summary>
            TokenIntegrityLevel,

            TokenUIAccess, TokenMandatoryPolicy, TokenLogonSid, MaxTokenInfoClass
        }

        public enum IntegrityLevel
        {
            Low, Medium, High, System, None, Unknown
        }

        const int ERROR_INVALID_PARAMETER = 87;

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool CloseHandle(IntPtr hHandle);


        public static IntegrityLevel GetIntegrityLevel(Process process)
        {
            try
            {
                IntPtr pId = (process.Handle);

                IntPtr hToken = IntPtr.Zero;
                if (OpenProcessToken(pId, TOKEN_QUERY, out hToken))
                {
                    try
                    {
                        IntPtr pb = Marshal.AllocCoTaskMem(1000);
                        try
                        {
                            uint cb = 1000;
                            if (GetTokenInformation(hToken, TOKEN_INFORMATION_CLASS.TokenIntegrityLevel, pb, cb, out cb))
                            {
                                IntPtr pSid = Marshal.ReadIntPtr(pb);

                                int dwIntegrityLevel = Marshal.ReadInt32(GetSidSubAuthority(pSid, (Marshal.ReadByte(GetSidSubAuthorityCount(pSid)) - 1U)));

                                if (dwIntegrityLevel == SECURITY_MANDATORY_LOW_RID)
                                {
                                    return IntegrityLevel.Low;
                                }
                                else if (dwIntegrityLevel >= SECURITY_MANDATORY_MEDIUM_RID && dwIntegrityLevel < SECURITY_MANDATORY_HIGH_RID)
                                {
                                    // Medium Integrity
                                    return IntegrityLevel.Medium;
                                }
                                else if (dwIntegrityLevel >= SECURITY_MANDATORY_HIGH_RID)
                                {
                                    // High Integrity
                                    return IntegrityLevel.High;
                                }
                                else if (dwIntegrityLevel >= SECURITY_MANDATORY_SYSTEM_RID)
                                {
                                    // System Integrity
                                    return IntegrityLevel.System;
                                }
                                return IntegrityLevel.None;
                            }
                            else
                            {
                                return IntegrityLevel.Unknown;
                            }
                        }
                        finally
                        {
                            Marshal.FreeCoTaskMem(pb);
                        }
                    }
                    finally
                    {
                        CloseHandle(hToken);
                        
                    }
                }
            }
            catch (Win32Exception ex)
            {
                return IntegrityLevel.Unknown;
            }

            //If we made it this far through all of the finally blocks and didn't return, then return unknown
            return IntegrityLevel.Unknown;
        }
    }
}
