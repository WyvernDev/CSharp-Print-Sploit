﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Diagnostics;

namespace calling_print_externally
{
    internal class Program
    {
        public const int print_address = 0x824A30;
        public static IntPtr handle;
        public static int base_addr;

        public static int aslr(int addr)
        {
            return ((addr - 0x400000) + base_addr);
        }

        public static IntPtr GetBaseAddress(Process proc)
        {
            return proc.MainModule.BaseAddress;
        }

        public static int get_relative(int func, int loc)
        {
            return (func - loc) - 5;
        }

        public static bool wpm(IntPtr addr, byte[] mem)
        {
            return winapi_functions.WriteProcessMemory(handle, addr, mem, (uint)mem.Length, out _);
        }

        static void inject_code_and_print(int type, string text)
        {
            var shellcode_mem = winapi_functions.VirtualAllocEx(handle, IntPtr.Zero, (uint)shellcode.total_bytes, winapi_functions.MEM_COMMIT | winapi_functions.MEM_RESERVE, winapi_functions.PAGE_EXECUTE_READWRITE);
            var string_mem = winapi_functions.VirtualAllocEx(handle, IntPtr.Zero, (uint)text.Length, winapi_functions.MEM_COMMIT | winapi_functions.MEM_RESERVE, winapi_functions.PAGE_EXECUTE_READWRITE);

            wpm(shellcode_mem, shellcode.data);
            wpm(string_mem, Encoding.UTF8.GetBytes(text));

            wpm(shellcode_mem + shellcode.string_pointer_offset, BitConverter.GetBytes((int)string_mem));
            wpm(shellcode_mem + shellcode.print_type_offset, new byte[] { (byte)type });

            var func_ptr = get_relative(aslr(print_address), (shellcode_mem + shellcode.function_pointer_offset).ToInt32()) + 1;
            var func_ptr_bytes = BitConverter.GetBytes(func_ptr);

            wpm(shellcode_mem + shellcode.function_pointer_offset, func_ptr_bytes);

            var thread = winapi_functions.CreateRemoteThread(handle, IntPtr.Zero, 0, shellcode_mem, IntPtr.Zero, 0, IntPtr.Zero);

            if (winapi_functions.WaitForSingleObjectEx(thread, 0xFFFFFFFF, false) == 0)
                winapi_functions.VirtualFreeEx(handle, shellcode_mem, 0, winapi_functions.MEM_RELEASE);
        }

        static void Main(string[] args)
        {
            Console.Title = "External printsploit in C#";

            var rbx_processes = Process.GetProcessesByName("RobloxPlayerBeta");

            if (rbx_processes.Length != 1)
                return;

            var proc_id = rbx_processes[0].Id;
            base_addr = GetBaseAddress(rbx_processes[0]).ToInt32();

            Program.handle = winapi_functions.OpenProcess(winapi_functions.PROCESS_CREATE_THREAD | winapi_functions.PROCESS_QUERY_INFORMATION | winapi_functions.PROCESS_VM_OPERATION | winapi_functions.PROCESS_VM_WRITE | winapi_functions.PROCESS_VM_READ,
                false, proc_id);

            while (true)
            {
                Console.Write("Enter print type (0-3): ");
                var print_type = int.Parse(Console.ReadLine());

                if (print_type < 0 || print_type > 3)
                {
                    Console.WriteLine("Please pick a number between 0 and 3!");
                    continue;
                }

                Console.Write("Enter text to print: ");
                var text = Console.ReadLine();
                inject_code_and_print(print_type, text);
                Console.WriteLine();
            }
        }
    }
}
