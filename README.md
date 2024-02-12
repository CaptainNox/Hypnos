# Hypnos 

(Still under development)

## A more reliable way of calling syscalls indirectly

### How does Hypnos work?

Hypnos works by spawning a suspended process, and utilizing this process to create a copy of `ntdll.dll`. From that copy, the syscall numbers are being resolved.

The `parent process ID` of the spawned process is being spoofed, to make the parent-child relation less suspicious.

Because the NTDLL copy is made from a suspended process, the NTAPI (Native WinAPI) functions aren't hooked by AV/EDR.

### How is this better?

This is better than the previous methods (Hell's Gate and Halo's Gate) because Hell's Gate doesn't work when the syscalls are hooked, and Halo's Gate is unreliable as it relies on incremental syscall numbers. Which is not the case for Windows 11.

We are also not overwriting the `.text` section of the loaded `ntdll.dll`, leaving the hooks intact. 

This is a pretty reliable way of resolving syscall numbers, which will most likely continue to work for further Windows releases.

### Features

 - PPID spoofing for suspended process
 - Calling syscalls indirectly
 - Utilizing hardware breakpoints to create a clean callstack

### How to use?

First of all, you have to use the `InitHypnos()`. This will place the initial breakpoint, and register the Vectored Exception Handler (VEH).
Then, you need to prepare the syscall by calling `PrepareSyscall()`.
Now you can execute the NTAPI function as you wish!

### Credits
 - [Original Hells Gate](https://github.com/am0nsec/HellsGate)
 - [0xCarnage](https://github.com/0xCarnage), thanks for the help
 - [HWSyscalls](https://github.com/ShorSec/HWSyscalls)
