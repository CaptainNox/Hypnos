MAKEFLAGS += -s

COMPILER_x86 		= i686-w64-mingw32-gcc
COMPILER_x64 		= x86_64-w64-mingw32-gcc

CFLAGS 			= -masm=intel

INCLUDE			= -I include
SOURCE 			= $(wildcard src/*.c)

%.o : %.asm
	echo "[-] Building syscall.asm"
	nasm -f win64 $< -o $@

all: x64

x64: src/syscall.o
	$(COMPILER_x64) src/*.o $(INCLUDE) $(SOURCE) $(CFLAGS) -o bin/hypnos.exe -DDEBUG -lntdll -DWIN_X64

