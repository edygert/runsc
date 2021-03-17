# runsc

This code is based on the code from
https://github.com/Kdr0x/Kd_Shellcode_Loader by Gary "kd" Contreras. This
version has been generally cleaned up and uses a single source file that can
be compiled for either 32 or 64-bit. The ability to specify an offset at
which the shellcode starts and specify a file to open were added.

Usage: runsc <offset> or runsc <offset> <filename of document to open for shellcode to find>

Shellcode must be in the current directory in a file named shellcode'.

The offset is required and must be the first parameter, but will often be 0.
The offset may be entered using decimal numbers or hex (prefixed by 0x).

Some shellcode looks for the next malware stage in the document in which
it is embedded. Supply the filename of that document as the third parameter
for that malware. This parameter is optional.

Run this program from the command line, after which you will need to
attach to it using the debugger. The address of the shellcode will be
printed on the screen. This is the address at which to set a breakpoint
in the debugger.