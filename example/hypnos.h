#pragma once
#include <stdio.h>
#include <windows.h>
#include <tlhelp32.h>

#include "Native.h"

#define X64_PEB_OFFSET 0x60
#define STACK_ARGS_LENGTH 8
#define STACK_ARGS_RSP_OFFSET 0x28
#define HYPNOS_DEBUG 1

#if HYPNOS_DEBUG == 1
#define DBG_PRINT(msg, ...) printf(msg, ##__VA_ARGS__);
#else
#define DBG_PRINT(msg, ...);
#endif

typedef BOOL(WINAPI* GetThreadContext_t)(
_In_ HANDLE hThread,
_Inout_ LPCONTEXT lpContext
);

typedef BOOL(WINAPI* SetThreadContext_t)(
_In_ HANDLE hThread,
_In_ CONST CONTEXT* lpContext
);

BOOL InitHypnos();
BOOL DeinitHypnos();
UINT64 PrepareSyscall(PCHAR symbolName);