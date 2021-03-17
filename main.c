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
#include "getopt.h"

#pragma comment(lib, "Shlwapi.lib")
#pragma comment(lib, "Ws2_32.lib")

const DWORD MEGABYTE = 1024 * 1024;

const char* shellcodefilename = "\\shellcode";

const char* helpText =
"\nUsage: runsc -f <shellcode file> -o <offset> -d <document file> -n\n\n"
"\n-h: Display this help text.\n"
"-f: The name of the file in which shellcode resides (required).\n"
"-o: The offset at which the shellcode begins (optional, default is 0). The offset may\n"
"be entered using decimal numbers or hex (prefixed by 0x).\n"
"-d: The name of a document file that shellcode may need to be loaded in memory (optional).\n"
"Some shellcode looks for the next malware stage in the document in which\n"
"it is embedded. Supply the filename of that document for this parameter.\n"
"-n: The default behavior is to run the shellcode as a suspended thread to give\n"
"you time to attach to this process with a debugger. If you just want to run the\n"
"shellcode and monitor it using behavior analysis tool, specify this option.\n\n"
"Run this program from the command line, after which you will need to\n"
"attach to it using the debugger (if -n is not specified). The address of the shellcode\n"
"will be printed on the screen. This is the address at which to set a breakpoint\n"
"in the debugger."
"\n\n";

// This code is from https://stackoverflow.com/questions/8046097/how-to-check-if-a-process-has-the-administrative-rights
static BOOL IsElevated()
{
	BOOL fRet = FALSE;
	HANDLE hToken = NULL;
	if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
		TOKEN_ELEVATION Elevation;
		DWORD cbSize = sizeof(TOKEN_ELEVATION);
		if (GetTokenInformation(hToken, TokenElevation, &Elevation, sizeof(Elevation), &cbSize)) {
			fRet = Elevation.TokenIsElevated;
		}
	}
	if (hToken) {
		CloseHandle(hToken);
	}
	return fRet;
}

int main(int argc, char** argv)
{
	char* shellcodeFile = NULL;
	int radix = 10;
	DWORD offset = 0;
	char* docFile = NULL;
	BOOL nopause = FALSE;

	int c;
	while ((c = getopt(argc, argv, "f:o:d:nh")) != -1) {
		switch (c) {
		case 'h':
			printf(helpText);
			return 1;

		case 'f':
			shellcodeFile = optarg;
			break;

		case 'o':
			if (strchr(optarg, 'x') || strchr(optarg, 'X')) {
				radix = 16;
			}

			offset = (DWORD)strtol(optarg, NULL, radix);
			if (offset < 0) {
				printf("[!] Error: Offset must be between 0 and the size of the shellcode.");
				return 1;
			}

			// if strtol returned 0 but the user specified something other than 0, 0x0, or 0X0, then
			// the offset was invalid.
			if (offset == 0 && (strcmp(optarg, "0") != 0 || _stricmp(optarg, "0x") != 0)) {
				printf("[!] Error: Offset must be between 0 and the size of the shellcode.");
				return 1;
			}
			break;

		case 'd':
			docFile = optarg;
			break;

		case 'n':
			nopause = TRUE;
			break;

		case '?':
			printf(helpText);
			return 1;

		default:
			return 1;
		}
	}

	if (shellcodeFile == NULL) {
		printf("[!] Error: shellcode file must be specified.");
		return 1;
	}

	if (!PathFileExistsA(shellcodeFile)) {
		printf("[!] Error: Shellcode file not found: %s\n\n", shellcodeFile);
		return 1;
	}
	printf("[*] Shellcode file: %s\n\n", shellcodeFile);

	if (docFile != NULL) {
		if (!PathFileExistsA(docFile)) {
			printf("[!] Error: Document file not found: %s\n\n", docFile);
			return 1;
		}
		printf("[*] Document file: %s\n\n", docFile);
	}

	// This was only included so that ws2_32.dll would be loaded; easier to set breakpoints!
	WSADATA wsaData;
	WSAStartup(MAKEWORD(2, 2), &wsaData);

	if (!IsElevated()) {
		printf("[!] Warning: You may not be running with admin rights. It is recommended that you do so when analyzing shellcode :)\n\n");
	}

	HANDLE hSCFile = CreateFileA(shellcodeFile, GENERIC_READ,
		FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
		OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);

	DWORD fsHigh = 0;  // High 32-bits of file size
	DWORD fsLow = GetFileSize(hSCFile, &fsHigh);

	if (fsHigh > 0) {
		printf("[!] Sanity check error: There's no way the shellcode payload is that large!\n\n");
		return 1;
	}
	printf("[*] Size of shellcode is %u bytes\n\n", fsLow);

	if (offset >= fsLow) {
		printf("[!] Error: Offset must be between 0 and the size of the shellcode.");
		return 1;
	}

	// Allocate space for the shellcode (VirtualAlloc will zero the space)
	char* scBuffer = (char*)VirtualAlloc(NULL, fsLow, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (scBuffer == NULL) {
		printf("[!] Error: Failed to allocate memory for shellcode!\n\n");
		return 1;
	}
	printf("[*] Shellcode buffer space of %u bytes allocated at address 0x%p\n\n", fsLow, scBuffer + offset);

	DWORD bytesRead = 0;

	SetFilePointer(hSCFile, 0, NULL, FILE_BEGIN);
	if (!ReadFile(hSCFile, scBuffer, fsLow, &bytesRead, NULL)) {
		printf("[!] Error: Failed to read data from shellcode file!\n\n");
		return 1;
	}

	printf("[*] Successfully read %u bytes into buffer!\n\n", fsLow);

	if (docFile != NULL) {
		HANDLE hDoc = CreateFileA(docFile, GENERIC_READ, FILE_SHARE_READ, NULL,
		   OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		if (hDoc == INVALID_HANDLE_VALUE) {
			printf("[!] Error: Could not open document file: %s\n\n", docFile);
			return 1;
		}
		printf("[*] Document file handle: %p\n\n", hDoc);
	}

	// Create the thread in a suspended or not state, depending on the -n option.
	// Also pass the address of the shellcode as a parameter because some
	// shellcode expects its address to be on the stack.
	DWORD threadID = 0;
	char *shellcodeAddress = scBuffer + offset;
	DWORD creationFlags = CREATE_SUSPENDED;
	if (nopause) {
		creationFlags = 0;
	}

	HANDLE hThread = CreateThread(NULL, MEGABYTE, (LPTHREAD_START_ROUTINE)(scBuffer + offset), &shellcodeAddress, creationFlags, &threadID);
	if (hThread == NULL) {
		printf("[!] Could not create shellcode thread.\n");
		return 1;
	}

	printf("[*] Thread ID %u (0x%X) was spawned to launch the shellcode; check it in the debugger!", threadID, threadID);
	WaitForSingleObject(hThread, INFINITE);

	VirtualFree(scBuffer, 0, MEM_RELEASE);

	return 0;
}

