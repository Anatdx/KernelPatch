# Guide

## How KernelPatch Works

KernelPatch consists of two core components: kpimg and kpuser.

### [kpimg](/kernel/)

- kpimg is a specially designed ELF.  
- kpimg takes over the kernel boot process, performs all kernel dynamic patching, and exports functionality for user use via system calls.  
- If you don't need extensive functionalities or want customization, you can separately utilize the code in [kernel/base](/kernel/base).

- [SuperCall](./super-syscall.md)

- [Kernel Inline Hook](./inline-hook.md)

- [Kernel Patch Module](./module.md)

### [kpuser](/user/)

kpuser is the user space header file and library for KernelPatch. You can directly embed kpuser into your program.
