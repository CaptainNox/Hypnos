# Hypnos

## A more reliable way of calling syscalls directly

### How does Hypnos work?

Hypnos works by spawning a suspended process, and utilizing this process to create a copy of NTDLL. From that copy, the SSNs are being resolved.

The PPID of the spawned process is being spoofed, to make the parent-child relationship match.

### Why?

We do this because Hell's Gate fails when functions are hooked. This is more reliable than Halo's gate, because we don't have to rely on SSNs being incremental.

