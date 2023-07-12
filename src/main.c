#include <stdio.h>
#include <stdlib.h>

#include "includes/inject.h"
#include "includes/sysgate.h"

#define PRINT_SUCCESS(msg) printf("[+] %s\n", msg);

int main() {
    PSYSCALL_TABLE syscallTable = InitSyscalls();
    PRINT_SUCCESS("Initialized syscall table!");

    ShellcodeInject(syscallTable);

    free(syscallTable);
    getchar();
    return 0;
}
