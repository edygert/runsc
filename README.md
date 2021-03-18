# runsc

This code is based on the code from
https://github.com/Kdr0x/Kd_Shellcode_Loader by Gary "kd" Contreras and contains additional functionality.
This source file can be compiled for either 32 or 64-bit.

Usage: ```runsc -f <shellcode file> [-o <offset>] [-d <document file>] [-n]```

-h: Display this help text.

-f: REQUIRED. The name of the file in which shellcode resides.

-o: OPTIONAL: The offset at which the shellcode begins (default is 0). The offset may
be entered using decimal numbers or hex (prefixed by 0x).

-d: OPTIONAL: The name of a document file that shellcode may need to be loaded in memory.
Some shellcode looks for the next malware stage in the document in which it is embedded.

-n: OPTIONAL: The default behavior is to run the shellcode as a suspended thread to give
you time to attach to this process with a debugger. If you just want to run the shellcode
and monitor it using behavior analysis tools, specify this option.

Run this program from the command line, after which you will need to attach to it using
the debugger (if -n is not specified). The address of the shellcode will be printed on
the screen. Set a breakpoint on this address in the debugger.
