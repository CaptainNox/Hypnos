#pragma once
#include <windows.h>
#include <tlhelp32.h>

typedef struct {
    unsigned long hash;
    WORD num;
} SYSCALL_TABLE_ENTRY, * PSYSCALL_TABLE_ENTRY;

typedef struct {
    SYSCALL_TABLE_ENTRY NtAllocateVirtualMemory;
    SYSCALL_TABLE_ENTRY NtProtectVirtualMemory;
    SYSCALL_TABLE_ENTRY NtCreateThreadEx;
    SYSCALL_TABLE_ENTRY ZwOpenProcess;
} SYSCALL_TABLE, * PSYSCALL_TABLE;

extern void PrepareSyscall(DWORD num);
extern NTSTATUS InvokeSyscall();

PSYSCALL_TABLE InitSyscalls();
