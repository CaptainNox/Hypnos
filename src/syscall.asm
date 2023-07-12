; Syscall stub for Windows

global PrepareSyscall
global InvokeSyscall

section .text
    PrepareSyscall:
	xor r11, r11
	mov r11d, ecx
        ret

    InvokeSyscall:
        mov r10, rcx
        mov eax, r11d

        syscall
        ret

end
