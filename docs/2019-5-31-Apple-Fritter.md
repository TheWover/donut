---
layout: post
title: Donut v0.9.1 "Apple Fritter" - Dual-Mode Shellcode, AMSI, and More
---

*TLDR: Version v0.9.1 "Apple Fritter" of Donut has been released, including dual-mode (AMD64+x86) shellcode, AMSI bypassing for .NET v4.8, automatic version detection of payloads, better support for Program.Main().*

# Introduction

In case you are unaware, [Donut](https://github.com/TheWover/donut "Donut") is a shellcode generation tool that creates native shellcode payloads from .NET Assemblies. This shellcode may be used to inject the Assembly into arbitrary Windows processes. Given an arbitrary .NET Assembly, parameters, and an entry point (such as Program.Main), it produces position-independent shellcode that loads it from memory. The .NET Assembly can either be staged from a URL or stageless by being embedded directly in the shellcode. Either way, the .NET Assembly is encrypted with the Chaskey block cipher and a 128-bit randomly generated key. After the Assembly is loaded through the CLR, the original reference is erased from memory to deter memory scanners. The Assembly is loaded into a new Application Domain to allow for running Assemblies in disposable AppDomains.

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
4) Since the x64 PIC is immediately following the previous instruction in memory, ```eip``` is now pointing at the first instruction in the x64 PIC. It now executes.

Starting in the v0.9.1 "Apple Fritter" release, dual-mode shellcode is the default. You may still tell Donut to produce x86 or x64 shellcode, rather than AMD64+x86.

Naturally, the dual-mode PIC will be larger than the other options. If the size of the PIC matters, use the version for the particular process you are targeting. Or, have your injector check the architecture of the target process before injecting into it. If not, use the dual-mode version to ensure maximum compatbility with host processes.

## Auto-Detect CLR Version

Rather than require the user to specify the CLR version, we now read the headers of the .NET Assembly to determine the appropriate CLR version.

The .NET Assembly file format is an extension of the regular [PE Format](https://en.wikipedia.org/wiki/Portable_Executable) used by Windows executables. One of the optional fields used by .NET is the ```IMAGE_COR20_HEADER```, which references a ```STORAGESIGNATURE``` structure containing the version details necessary to load the correct runtime. We check the ```iVersionString``` variable to get the exact version requirement for your Assembly. Please note, the names of these data structures and variables are somewhat arbitrary. I am borrowing [dnSpy's](https://github.com/0xd4d/dnSpy) terminology so that I can show you these two pretty pictures.

The relevant layout of the .NET headers in my SafetyKatz DLL as stored on disk:

![_config.yml]({{ site.baseurl }}/images/Apple_Fritter/headers_in_PE.PNG)

And what the ```STORAGESIGNATURE``` structure actually looks like:

![_config.yml]({{ site.baseurl }}/images/Apple_Fritter/structured_headers.PNG)

If you do not want us to automatically determine the version number, you may still manually specify what version to use with the `-r` flag.


## Main Entry Point

The original version of Donut did not handle Main entry points for EXEs well due to the fact that it uses an object array as its function signature rather than a string array. We now correctly handle this so that you don't have to know about the difference. :-)

## AMSI Patching

To provide some context, AMSI integration has been added to the new version of the .NET Framework. It has also been ported to [.NET Core](https://github.com/dotnet/coreclr/issues/21370).

Specifically, AMSI integration was added to the CLR itself so that any .NET Assemblies loaded from memory will be scanned with ```AmsiScanBuffer``` from ```amsi.dll``` before they are loaded. If the result of ```AmsiScanBuffer``` is anything but ```S_OK``` it will return an ```HRESULT``` error code. This affects everything that loads Assemblies from memory using the CLR, including ```System.Reflection.Assembly.Load```, Donut shellcode, and (presumably if I could test it) Cobalt Strike's ```execute-assembly``` command.

When you try to load a .NET Assembly from memory that is known to be malicious, you get a Defender alert that looks like the picture below. Notice that data source was AMSI, and that the process it was running in is ```notepad.exe```. The assembly was injected into notepad through Donut shellcode.

![_config.yml]({{ site.baseurl }}/images/Apple_Fritter/donut_AMSI.PNG)
 
However, their implementation of AMSII integration is subject to memory patching bypasses in the same way that PowerShell is. We developed on existing research, produced some custom bypasses, and added a modular bypass system to Donut that lets you choose which technique you would like to use.

Odzhan wrote a [blog post](https://modexp.wordpress.com/2019/06/03/disable-amsi-wldp-dotnet/) detailing each of the AMSI bypasses we added to Donut. It is important to note that there could be many more. I believe that anyone who sits down to do the research and develop an AMSI bypass will probably come up with their own slightly different variant. As long as Microsoft continues to rely on calling DLL functions from user-level memory space, AMSI will be subject to memory patching bypasses.

The result looks like the picture below. I safely injected SafetyKatz into ```notepad.exe``` using Donut shellcode, even thought AMSI was used. Defender shows no detections.

![_config.yml]({{ site.baseurl }}/images/Apple_Fritter/amsi_is_dead.PNG)

I must strongly emphasize, the fact that 4.8 AMSI can be bypassed like in PowerShell does NOT make it useless. This new AMSI is a *good thing* that will benefit .NET Security. It incurs cost upon adversaries. Use it. But also recognise that, like everything, it has its limitations.

### Modular Bypass System

As we researched bypasses for AMSI, it became clear that there is many ways to do it. It would be silly to force users of Donut to have to use whatever we came up with. As such, we ensured that you may easily add your own bypass or customize one of ours. The bypasses are defined in ```payload/bypass.c```. You may either modify our C code, or add your own. Each bypass implements the same ```BOOL DisableAMSI(PDONUT_INSTANCE inst)``` function and is wrapped in an ```#ifdef BYPASS_NAME``` preprocessor directive. To change which bypass is used, change the Makefile to define the bypass name specified by the directive.

For example, you could change the relevant line in ```payload/Makefile.msvc``` from

```
cl -DBYPASS_AMSI_A -DBYPASS_WLDP_A -Zp8 -c -nologo -Os -O1 -Gm- -GR- -EHa -Oi -GS- -I ..\include payload.c ..\hash.c ..\encrypt.c bypass.c clib.c
```

To:

```
cl -DBYPASS_AMSI_B -DBYPASS_WLDP_A -Zp8 -c -nologo -Os -O1 -Gm- -GR- -EHa -Oi -GS- -I ..\include payload.c ..\hash.c ..\encrypt.c bypass.c clib.c
```

In order to switch from using BypassA to BypassB.

This system not only makes it easy to change the bypass technique, but also reduces the size, complexity, and signaturability of the shellcode by ensuring that code you are not using is present in the PIC to be found by AV/EDR.

## Device Guard Dynamic Code Prevention Bypass

Windows Defender Device Guard includes an optional policy for disabling dynamically-generated .NET code from executing. Because it was mixed-in with the AMSI scanning code, we went ahead and disabled it too. Not sure if that will help anyone, but hey it was easy. ¯\_(ツ)_/¯

![_config.yml]({{ site.baseurl }}/images/Apple_Fritter/code_integrity.png)

# Conclusion

Donut v0.9.1 "Apple Fritter" represents the first improvements to Donut. More improvements are coming as we have time to make them. In the meantime, Donut is still in Beta so we welcome feedback and testing.

I know that several people have already had difficulties integrating Donut into their toolsets because of the complexity of the data structures it uses. To help with this, our plan for the full release (version 1.0) is to produce C# and Python generators. That will be the primary focus of our efforts moving forward.

## Plans

Below is the current version release plan for Donut.

* v0.9.1:
  * Dual-Mode shellcode that can run in either x64 for x86 (WOW64) processes.
  * Automatic detection of the CLR version required for .NET Assembly payloads.
  * AMSI bypassing for version .NET 4.8 that ensure all Assemblies can be safely loaded.
  * Modular system for adding bypasses. Your choide of bypass functionality is compiled into payload.exe based on compiler flags.
  * Bypass for Device Guard policy preventing execution of dynamically generated .NET code
  * Better handling of Main functions (Entry Points) that use an object array containing string arrays, rather than an array of strings
* v1.0:
  * C# generator
  * C# wrapper for our dynamic library
  * Python generator
  * Python wrapper for our dynamic library
  * Better documentation for debugging, designing with, and integrating Donut.
* v1.1:
  * Automatic unloading of Application Domains after the Assembly finishes executing.
  * Support for HTTP proxies
