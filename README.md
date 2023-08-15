# Hypnos 

## A more reliable way of calling syscalls indirectly

### How does Hypnos work?

Hypnos works by spawning a suspended process, and utilizing this process to create a copy of NTDLL. From that copy, the SSNs are being resolved.

The PPID of the spawned process is being spoofed, to make the parent-child relationship match.

Because the NTDLL copy is being made from a suspended process, the Win API functions are not hooked by AV/EDR.
### Why?

We do this because Hell's Gate fails when functions are hooked. This is more reliable than Halo's gate, because we don't have to rely on SSNs being incremental.

### TODO
 - Add hardware breakpoints to clean up the callstack
 - Add API hashing (DONE)
 - Runtime win api call resolving for ppid spoofing/pid searching

### Credits
 - [Original Hells Gate](https://github.com/am0nsec/HellsGate)
 - [0xCarnage](https://github.com/0xCarnage), thanks for the help
 - [HWSyscalls](https://github.com/ShorSec/HWSyscalls)
