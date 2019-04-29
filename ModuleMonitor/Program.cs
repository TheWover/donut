/*  Name: ModuleMonitor
 * 
 * 
 * 
 * 
 * 
 * 
 */

using System;
using System.Linq;
using System.Collections.Generic;
using System.Diagnostics;
using System.Management;
using System.Runtime.InteropServices;
using System.Security.Principal;

namespace CLRSentry
{
    class Program
    {
        //TODO: Rename projec to ModuleMonitor, and add a --clrssentry option to watch for CLR injection
        static void Main(string[] args)
        {
            if (args.Contains("-h") || args.Contains("--help"))
            {
                PrintUsage();

                Environment.Exit(0);
            }


            if (args.Contains("--clr-sentry"))
            {
                CLRSentry();
            }
            else
            {
  
                MonitorModuleLoads();

            }
        }

        /// <summary>
        /// Monitor for module loads using the WMI Event Win32_ModuleLoadTrace.
        /// </summary>
        public static void MonitorModuleLoads()
        {
            //Monitor without any filters
            MonitorModuleLoads(new List<string>());
        }

        /// <summary>
        /// Struct representing the WMI class Win32_ModuleLoadTrace 
        /// </summary>
        [StructLayout(LayoutKind.Sequential)]
        public struct Win32_ModuleLoadTrace
        {
            public sbyte[] SECURITY_DESCRIPTOR;
            public UInt64 TIME_CREATED;
            public string FileName;
            public UInt64 DefaultBase;
            public UInt64 ImageBase;
            public UInt32 ImageChecksum;
            public UInt64 ImageSize;
            public UInt32 ProcessID;
            public UInt32 TimeDateSTamp;
        }


        /// <summary>
        /// Overload of GetNextModuleLoad that does not require filters.
        /// </summary>
        /// <returns></returns>
        public static Win32_ModuleLoadTrace GetNextModuleLoad()
        {
            return GetNextModuleLoad(new List<string>());
        }


        /// <summary>
        /// Get the details of the next module load
        /// </summary>
        /// <param name="filters">Filenames to filter for.</param>
        /// <returns></returns>
        public static Win32_ModuleLoadTrace GetNextModuleLoad(List<string> filters)
        {
            Win32_ModuleLoadTrace trace = new Win32_ModuleLoadTrace();

            //Ideally, we would filter here to reduce the amount of events that we have to consume.
            //However, we cannot use the WHERE clause because the 
            var startWatch = new ManagementEventWatcher(new WqlEventQuery("SELECT * FROM Win32_ModuleLoadTrace"));

            ManagementBaseObject e = startWatch.WaitForNextEvent();

            //Instead, we filter here, because it's easy and we're a bit lazy
            if (filters.Count == 0 ^ filters.Contains(((ManagementBaseObject)e)["FileName"].ToString()))
            {
                if (((ManagementBaseObject)e)["SECURITY_DESCRIPTOR"] != null)
                    trace.SECURITY_DESCRIPTOR = (sbyte[])((ManagementBaseObject)e)["SECURITY_DESCRIPTOR"];

                if (((ManagementBaseObject)e)["TIME_CREATED"] != null)
                    trace.TIME_CREATED = (UInt64)((ManagementBaseObject)e)["TIME_CREATED"];
                
                if (((ManagementBaseObject)e)["FileName"] != null)
                    trace.FileName = (string)((ManagementBaseObject)e)["FileName"];

                if (((ManagementBaseObject)e)["DefaultBase"] != null)
                    trace.DefaultBase = (UInt64)((ManagementBaseObject)e)["DefaultBase"];

                if (((ManagementBaseObject)e)["ImageBase"] != null)
                    trace.ImageBase = (UInt64)((ManagementBaseObject)e)["ImageBase"];

                if (((ManagementBaseObject)e)["ImageChecksum"] != null)
                trace.ImageChecksum = (UInt32)((ManagementBaseObject)e)["ImageChecksum"];

                if (((ManagementBaseObject)e)["ImageSize"] != null)
                    trace.ImageSize = (UInt64)((ManagementBaseObject)e)["ImageSize"];

                if (((ManagementBaseObject)e)["ProcessID"] != null)
                    trace.ProcessID = (UInt32)((ManagementBaseObject)e)["ProcessID"];

                if (((ManagementBaseObject)e)["TimeDateSTamp"] != null)
                    trace.TimeDateSTamp = (UInt32)((ManagementBaseObject)e)["TimeDateSTamp"];

                return trace;
            }
            else
                return trace;
        }

        public static void CLRSentry()
        {
            //Sentries never sleep.
            //UCMJ Article 113
            /* Any sentinel or look-out who is found drunk or sleeping upon his post, 
             * or leaves it before he is regularly relieved, shall be punished, 
             * if the offense is committed in time of war, by death or such other punishment as a court-martial may direct, 
             * by if the offense is committed at any other time, 
             * by such punishment other than death as court-martial may direct.
             */
            while (true)
            {
                //Get the module load.
                Win32_ModuleLoadTrace trace = GetNextModuleLoad();

                //Split the 
                string[] parts = trace.FileName.Split('\\');

                //Check whether it is a .NET Runtime DLL
                if (parts[parts.Length - 1].Contains("msco"))
                {
                    Process proc = Process.GetProcessById((int) trace.ProcessID);

                    //Check if the file is a .NET Assembly
                    if (!IsValidAssembly(proc.StartInfo.FileName))
                    {
                        //If it is not, then the CLR has been injected.
                        Console.WriteLine();

                        Console.WriteLine("[!] CLR Injection has been detected!");

                        //Display information from the event
                        Console.WriteLine("[>] Process {0} has loaded the CLR but is not a .NET Assembly:", trace.ProcessID);
                        Console.WriteLine("{0,15} Win32_ModuleLoadTrace:", "[!]");

                        DateTime time = new DateTime();
                        DateTime.TryParse(trace.TIME_CREATED.ToString(), out time);
                        time.ToLocalTime();

                        //TODO: Time is printing strangley
                        Console.WriteLine("{0,15} (Event)   TIME_CREATED: {1}", "[+]", time.ToString());
                        //TODO: Convert to hex
                        Console.WriteLine("{0,15} (Process) ImageBase: {1}", "[+]", trace.ImageBase);
                        Console.WriteLine("{0,15} (Process) DefaultBase: {1}", "[+]", trace.DefaultBase);
                        Console.WriteLine("{0,15} (Module)  FileName: {1}", "[+]", trace.FileName);
                        Console.WriteLine("{0,15} (Module)  TimeStamp: {1}", "[+]", trace.TimeDateSTamp);
                        Console.WriteLine("{0,15} (Module)  ImageSize: {1}", "[+]", trace.ImageSize);
                        Console.WriteLine("{0,15} (Module)  ImageChecksum: {1}", "[+]", trace.ImageChecksum);

                        Console.WriteLine("{0,15} Additional Information:", "[>]");

                        Process process = SafeGetProcessByID(int.Parse(trace.ProcessID.ToString()));

                        if (process != null)
                        {

                            Console.WriteLine("{0,30} Process Name: {1}", "[+]", process.ProcessName);
                            Console.WriteLine("{0,30} Process User: {1}", "[+]", GetProcessUser(process));
                        }
                    }
                }
            }
        }

        /// <summary>
        /// Check if the file is a .NET Assembly by cheating and using the Reflection API's PE Parser.
        /// 
        /// https://stackoverflow.com/questions/36797939/how-to-test-whether-a-file-is-a-net-assembly-in-c-sharp
        /// </summary>
        /// <param name="path">The file to check</param>
        /// <returns>True if a .NET Assembly, false if not. Hopefully.</returns>
        public static bool IsValidAssembly(string path)
        {
            try
            {
                // Attempt to resolve the assembly
                var assembly = System.Reflection.AssemblyName.GetAssemblyName(path);
                // Nothing blew up, so it's an assembly
                return true;
            }
            catch (Exception ex)
            {
                // Something went wrong, it is not an assembly (specifically a 
                // BadImageFormatException will be thrown if it could be found
                // but it was NOT a valid assembly
                return false;
            }
        }


        /// <summary>
        /// Monitor for module loads using the WMI Event Win32_ModuleLoadTrace. Optionally filter by module names.
        /// </summary>
        /// <param name="filters">A list of module names to filter for.</param>
        public static void MonitorModuleLoads(List<string> filters)
        {
            Console.WriteLine("Monitoring Win32_ModuleLoadTrace...\n");

            while (true)
            {
                Win32_ModuleLoadTrace trace = new Win32_ModuleLoadTrace();
                Win32_ModuleLoadTrace tracecomp = new Win32_ModuleLoadTrace();

                //Get the details of the next module load
                trace = GetNextModuleLoad(filters);

                //If the trace is not empty
                if (!trace.Equals(tracecomp))
                {
                    Console.WriteLine();

                    //Display information from the event
                    Console.WriteLine("[>] Process {0} has loaded a module:", trace.ProcessID);
                    Console.WriteLine("{0,15} Win32_ModuleLoadTrace:", "[!]");

                    DateTime time = new DateTime();
                    DateTime.TryParse(trace.TIME_CREATED.ToString(), out time);
                    time.ToLocalTime();

                    //TODO: Time is printing strangley
                    Console.WriteLine("{0,15} (Event)   TIME_CREATED: {1}", "[+]", time.ToString());
                    //TODO: Convert to hex
                    Console.WriteLine("{0,15} (Process) ImageBase: {1}", "[+]", trace.ImageBase);
                    Console.WriteLine("{0,15} (Process) DefaultBase: {1}", "[+]", trace.DefaultBase);
                    Console.WriteLine("{0,15} (Module)  FileName: {1}", "[+]", trace.FileName);
                    Console.WriteLine("{0,15} (Module)  TimeStamp: {1}", "[+]", trace.TimeDateSTamp);
                    Console.WriteLine("{0,15} (Module)  ImageSize: {1}", "[+]", trace.ImageSize);
                    Console.WriteLine("{0,15} (Module)  ImageChecksum: {1}", "[+]", trace.ImageChecksum);

                    Console.WriteLine("{0,15} Additional Information:", "[>]");

                    Process process = SafeGetProcessByID(int.Parse(trace.ProcessID.ToString()));

                    if (process != null)
                    {

                        Console.WriteLine("{0,30} Process Name: {1}", "[+]", process.ProcessName);
                        Console.WriteLine("{0,30} Process User: {1}", "[+]", GetProcessUser(process));
                    }
                }
            }
        }

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);
        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CloseHandle(IntPtr hObject);

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
            catch (Exception ex)
            {
                return ex.Message;
            }
            finally
            {
                if (processHandle != IntPtr.Zero)
                {
                    CloseHandle(processHandle);
                }
            }
        }//end method


        /// <summary>
        /// Try to get the process by ID and return null if it no longer exists.
        /// </summary>
        /// <param name="id"></param>
        /// <returns></returns>
        private static Process SafeGetProcessByID(int id)
        {
            try
            {
                return Process.GetProcessById(id);

            }
            catch
            {
                return null;
            }
        }

        private static void PrintUsage()
        {
            Console.WriteLine();
            Console.WriteLine("| Module Monitor [v0.1]");
            Console.WriteLine("| Copyright (c) 2019 TheWover");
            Console.WriteLine();

            Console.WriteLine("Usage: ModuleMonitor.exe [--clr-sentry]");
            Console.WriteLine();

            Console.WriteLine("{0,-5} {1,-20} {2}", "", "-h, --help", "Display this help menu.");
            Console.WriteLine("{0,-5} {1,-20} {2}", "", "--clr-sentry", "Monitor for CLR injection.");
            Console.WriteLine();

            Console.WriteLine("Examples:");
            Console.WriteLine();

            Console.WriteLine("ModuleMonitor.exe");
            Console.WriteLine("ModuleMonitor.exe --clr-monitor");
            Console.WriteLine();
        }
    }//end class
}//end namespace
