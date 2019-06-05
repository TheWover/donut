---
layout: post
title: Donut v0.9.1 "Apple Fritter" - Dual-Mode Shellcode, AMSI, and More
---

*TLDR: Version v0.9.1 "Apple Fritter" of Donut has been released, including dual-mode (AMD64+x86) shellcode, AMSI bypassing for .NET v4.8, automatic version detection of payloads, better support for Program.Main().*

# Introduction

In case you are unaware, [Donut](https://github.com/TheWover/donut "Donut) is a shellcode generation tool that creates native shellcode payloads from .NET Assemblies. This shellcode may be used to inject the Assembly into arbitrary Windows processes. Given an arbitrary .NET Assembly, parameters, and an entry point (such as Program.Main), it produces position-independent shellcode that loads it from memory. The .NET Assembly can either be staged from a URL or stageless by being embedded directly in the shellcode. Either way, the .NET Assembly is encrypted with the Chaskey block cipher and a 128-bit randomly generated key. After the Assembly is loaded through the CLR, the original reference is erased from memory to deter memory scanners. The Assembly is loaded into a new Application Domain to allow for running Assemblies in disposable AppDomains.

Today, we released version v0.9.1. The major features include:

* Dual-Mode shellcode that can run in either x64 for x86 (WOW64) processes.
* Automatic detection of the CLR version required for .NET Assembly payloads.
* AMSI bypassing for version .NET 4.8 that ensure all Assemblies can be safely loaded.
* Modular system for adding bypasses. Your choide of bypass functionality is compiled into payload.exe based on compiler flags.
* Bypass for Device Guard policy preventing execution of dynamically generated .NET code
* Better handling of Main functions (Entry Points) that use an object array containing string arrays, rather than an array of strings

# Feature Breakdown

## Dual-Mode Shellcode

Odzhan knew an old trick for crafting shellcode that can run in either x86 or x64 Windows processes using REX prefixes. We combine the x86 and x64 shellcode with a stub that "detects" the architecture of the process. The layout in memory looks like:

```
--------------------------------------------------
| detection stub | x64 shellcode | x86 shellcode |
--------------------------------------------------
```

And the logic:

```assembly
0x31C0  xor eax, eax        // null eax
0x48    dec eax             // decrement eax to produce an underflow
0x0F88  js dword x86_code   // jump to x86 payload if we are in a WOW64 process
<x64_code>                  // the x64 PIC machine code for the payload
<x86_code>                  // the x86 PIC machine code for the payload
```

There are two ways this code can execute.

If the process is WOW64 (x86):

1) ```eax``` will be nulled.
2) ```eax``` will be decremented, resulting in an underflow.
3) Since the sign flag is set from the underflow, the condition for the jump is satisfied. Jump to the x86 shellcode.

If the process is x64:

1) ```eax``` will be nulled.
2) ```0x48``` is an REX prefix for the next instruction
3) The previous REX prefix is not valid for the ```js``` instruction. As such, nothing happens.
4) Since the x64 PIC is immediately following the previous instruction in memory, ```eip`` is now pointing at the first instruction in the PIC. It now executes.

Starting in the v0.9.1 "Apple Fritter" release, dual-mode shellcode is the default. You may still tell Donut to produce x86 or x64 shellcode, rather than AMD64+x86.

Naturally, the dual-mode PIC will be larger than the other options. If the size of the PIC matters, use the version for the particular process you are targeting. Or, have your injector check the architecture of the target process before injecting into it. If not, use the dual-mode version to ensure maximum compatbility with host processes.

## Auto-Detect CLR Version

Rather than require the user to specify the CLR version, we will now read the headers of the .NET Assembly to determine the appropriate version. TODO: Specify the correct header that we modify.

## Main Entry Point



## AMSI Patching

Odzhan wrote a [blog post](https://modexp.wordpress.com/2019/06/03/disable-amsi-wldp-dotnet/) detailing each of the AMSI bypasses we added to Donut. It is important to note that there could be many more. I believe that anyone who sits down to do the research and develop an AMSI bypass will probably come up with their own slightly different variant. As long as Microsoft continues to rely on calling DLL functions from user-level memory space, AMSI will be subject to memory patching bypasses.

# Conclusion

## Plans

* v0.9.2: 
* v1.0: C# generator, Python generator. Better documentation for debugging, designing with, and integrating Donut.
