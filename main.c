// This code is based on the code from
// https://github.com/Kdr0x/Kd_Shellcode_Loader by Gary "kd" Contreras. This
// version has been generally cleaned up and uses a single source file that can
// be compiled for either 32 or 64-bit. The ability to specify a file to open
// and additional error checks were added too.

#include <stdio.h>
#include <stdlib.h>
#include <winsock2.h>
#include <ws2tcpip.h>

#include "Shlobj.h"
#include "shlwapi.h"
#include "windows.h"
#pragma comment(lib, "Shlwapi.lib")
#pragma comment(lib, "Ws2_32.lib")

const DWORD MEGABYTE = 1024 * 1024;

const char* shellcodefilename = "\\shellcode";

const char* helpText = "\nUsage: runsc <offset> or runsc <offset> <filename of document to open for shellcode to find>\n\n"
	"Shellcode must be in the current directory in a file named shellcode'.\n\n"
	"The offset is required and must be the first parameter, but will often be 0.\n"
	"The offset may be entered using decimal numbers or hex (prefixed by 0x).\n\n"
	"Some shellcode looks for the next malware stage in the document in which\n"
	"it is embedded. Supply the filename of that document as the third parameter\n"
	"for that malware. This parameter is optional.\n\n"
	"Run this program from the command line, after which you will need to\n"
	"attach to it using the debugger. The address of the shellcode will be\n"
	"printed on the screen. This is the address at which to set a breakpoint\n"
	"in the debugger."
	"\n\n";

int main(int argc, char** argv)
{
	if (argc < 2 || (argc >= 2 && strcmp(argv[1], "-h") == 0)) {
		printf(helpText);
		return 1;
	}

	// This was only included so that the ws2_32.dll
	// library would be loaded; easier to set breakpoints!
	WSADATA wsaData;
	WSAStartup(MAKEWORD(2, 2), &wsaData);

	if (IsUserAnAdmin()) {
		printf("[!] Warning: You may not be running with admin rights. It is recommended that you do so when analyzing shellcode :)\n\n");
	}

	// The full path to the shellcode file
	char fullPath[1024];

	memset(fullPath, 0, sizeof(fullPath));

	DWORD dwResult = GetCurrentDirectoryA(sizeof(fullPath), fullPath);
	if (dwResult == 0) {
		printf("[!] Error: GetCurrentDirectoryA failed\n");
		return 1;
	}
	printf("[*] The current \"working\" directory is: %s\n\n", fullPath);

	if (strlen(fullPath) + strlen(shellcodefilename) >= sizeof(fullPath)) {
		printf("[!] Error: length of full path to shellcode file is >= %d\n", (unsigned int)sizeof(fullPath));
		return 1;
	}

	strcat_s(fullPath, sizeof(fullPath), shellcodefilename);

	if (!PathFileExistsA(fullPath)) {
		printf("[!] Error: File not found: %s\n\n", fullPath);
		return 1;
	}
	printf("[*] File found: %s\n\n", fullPath);

	HANDLE hSCFile = CreateFileA(fullPath, GENERIC_READ,
		FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
		OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);

	DWORD fsHigh = 0;  // High 32-bits of file size
	DWORD fsLow = GetFileSize(hSCFile, &fsHigh);

	if (fsHigh > 0) {
		printf("[!] Sanity check error: There's no way the shellcode payload is that large!\n\n");
		return 1;
	}
	printf("[*] Size of shellcode is %u bytes\n\n", fsLow);

	int radix = 10;
	if (strchr(argv[1], 'x') || strchr(argv[1], 'X')) {
		radix = 16;
	}

	DWORD offset = (DWORD)strtol(argv[1], NULL, radix);
	if (offset >= fsLow || offset < 0) {
		printf("[!] Error: Offset must be between 0 and the size of the shellcode.");
		return 1;
	}

	// if strtol returned 0 but the user specified something other than 0, 0x0, 0X0, then
	// the offset was invalid.
	if (offset == 0 && (strcmp(argv[1], "0") != 0 || _stricmp(argv[1], "0x") != 0)) {
		printf("[!] Error: Offset must be between 0 and the size of the shellcode.");
		return 1;
	}

	// Allocate space for the shellcode (VirtualAlloc will zero the space)
	char* scBuffer = (char*)VirtualAlloc(NULL, fsLow, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (scBuffer == NULL) {
		printf("[!] Error: Failed to allocate memory for shellcode!\n\n");
		return 1;
	}
	printf("[*] Shellcode buffer space of %u bytes allocated at address 0x%p\n\n", fsLow, scBuffer);

	DWORD bytesRead = 0;

	SetFilePointer(hSCFile, 0, NULL, FILE_BEGIN);
	if (!ReadFile(hSCFile, scBuffer, fsLow, &bytesRead, NULL)) {
		printf("[!] Error: Failed to read data from shellcode file!\n\n");
		return 1;
	}

	printf("[*] Successfully read %u bytes into buffer!\n\n", fsLow);

	if (argc == 3) {
		HANDLE hDoc = CreateFileA(argv[2], GENERIC_READ, FILE_SHARE_READ, NULL,
		   OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		if (hDoc == INVALID_HANDLE_VALUE) {
			printf("[!] Error: Could not open document: %s\n\n", argv[2]);
			return 1;
		}
		printf("[*] Doc file handle: %p\n\n", hDoc);
	}

	// Create a suspended thread on the shellcode, adding the shellcode's location
	// as an argument (in case it's needed)
	DWORD threadID = 0;
	HANDLE hThread = CreateThread(NULL, MEGABYTE, (LPTHREAD_START_ROUTINE)(scBuffer + offset), scBuffer + offset, CREATE_SUSPENDED, &threadID);
	if (hThread == NULL) {
		printf("[!] Could not create shellcode thread.\n");
		return 1;
	}

	printf("[*] Thread ID %u (0x%X) was spawned to launch the shellcode; check it in the debugger!", threadID, threadID);
	WaitForSingleObject(hThread, INFINITE);

	VirtualFree(scBuffer, 0, MEM_RELEASE);

	return 0;
}
