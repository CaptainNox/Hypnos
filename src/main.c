#include <stdio.h>
#include <stdlib.h>

#include "includes/hypnos.h"

#define PRINT_SUCCESS(msg) printf("[+] %s\n", msg);

int main() {
    //PSYSCALL_TABLE syscallTable = InitSyscalls();
    PRINT_SUCCESS("Initialized syscall table!");

    getchar();
    return 0;
}
