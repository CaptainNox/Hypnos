# Hypnos 

## A more reliable way of calling syscalls indirectly

### How does Hypnos work?

Hypnos works by spawning a suspended process, and utilizing this process to create a copy of NTDLL. From that copy, the SSNs are being resolved.

The PPID of the spawned process is being spoofed, to make the parent-child relationship match.

Because the NTDLL copy is being made from a suspended process, the Win API functions are not hooked by AV/EDR.
### Why?

We do this because Hell's Gate fails when functions are hooked. This is more reliable than Halo's gate, because we don't have to rely on SSNs being incremental.

### Features

 - PPID spoofing for suspended process
 - Calling syscalls indirectly
 - Utilizing hardware breakpoints to create a clean callstack

### How to use?

First of all, you have to use the `InitHypnos()`. This will place the initial breakpoint, and register the vectored exception handler.
Then, you need to prepare the syscall by calling `PrepareSyscall()`.
Now you can execute the NTAPI function as you wish!

Look at the example in `example/` for a code snippet.

### Credits
 - [Original Hells Gate](https://github.com/am0nsec/HellsGate)
 - [0xCarnage](https://github.com/0xCarnage), thanks for the help
 - [HWSyscalls](https://github.com/ShorSec/HWSyscalls)
