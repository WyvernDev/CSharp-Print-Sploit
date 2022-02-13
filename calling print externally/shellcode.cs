using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace calling_print_externally
{
    class shellcode
    {
        public static int string_pointer_offset = 4;
        public static int print_type_offset = 9;
        public static int function_pointer_offset = 11;
        public static int total_bytes = 22;

        public static Byte[] data =
        {
            0x55,                                   // push ebp
            0x8b, 0xEC,                             // mov esp, ebp
            0x68, 0x00, 0x00, 0x00, 0x00,           // push string to print
            0x6A, 0x00,                             // push type of print
            0xE8, 0x00, 0x00, 0x00, 0x00,           // call print func
            0x83, 0xC4, 0x08,                       // add esp, 8
            0x8B, 0xE5,                             // mov esp, ebp
            0x5D,                                   // pop ebp
            0xC3                                    // ret
        };

    }
}
