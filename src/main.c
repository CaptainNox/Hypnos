#include <stdio.h>
#include <stdlib.h>

#include "includes/hypnos.h"

#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)

typedef NTSTATUS(NTAPI* pNtAllocateVirtualMemory_t)(
        HANDLE ProcessHandle,
        PVOID *BaseAddress,
        ULONG_PTR ZeroBits,
        PSIZE_T RegionSize,
        ULONG AllocationType,
        ULONG Protect
        );

int main() {
    if (InitHypnos()) {
        printf("[+] Hypnos initialized successfully!\n");
    }

    pNtAllocateVirtualMemory_t pNtAllocateVirtualMemory = (pNtAllocateVirtualMemory_t)PrepareSyscall((char*)"NtAllocateVirtualMemory");

    PVOID remoteBuffer = NULL;
    SIZE_T length = 120;

    NTSTATUS status = pNtAllocateVirtualMemory((HANDLE)-1, &remoteBuffer, 0, &length, MEM_COMMIT, PAGE_READWRITE);

    if (NT_SUCCESS(status)) {
        printf("[+] Allocated memory successfully!\n");
    }

    return 0;
}
