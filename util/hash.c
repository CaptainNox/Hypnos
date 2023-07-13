#include <stdio.h>

unsigned long djb2_hash(const char* str) {
    unsigned long hash = 5381;
    int c;

    while ((c = *str++))
        hash = ((hash << 5) + hash) + c; /* hash * 33 + c */

    return hash;
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        printf("Please enter the string to be hashed.\n");
        return 1;
    }

    printf("%s: 0x%lx\n", argv[1], djb2_hash(argv[1]));
    return 0;
}