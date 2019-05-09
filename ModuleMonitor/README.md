# ModuleMonitor

Has its own repo at: https://github.com/TheWover/ModuleMonitor

Uses WMI Event Win32_ModuleLoadTrace to monitor module loading. Provides filters, and detailed data. Has an option to monitor for CLR Injection attacks.

The CLR Sentry option follows some simple logic: If a process loads the CLR, but the program is not a .NET program, then the CLR has been injected into it.

While useful, there are both false positives and false negatives:

* False Postiive: There are (few) legitimate uses of the Unmanaged CLR Hosting API. If there weren't, then Microsoft wouldn't have made it. CLR Sentry will notice every unmanaged program that loads the CLR.  
* False Negatives: This will NOT notice injection of .NET code into processes that already have the CLR loaded. So, no use of the Reflection API and not when donut is used to inject shellcode into managed processes.

Please Note: This is intended only as a Proof-of-Concept to demonstrate the anomalous behavior produced by CLR injection and how it may be detected. It should not be used in any way in a production environment. You perform the same logic with the ``` Image Load ``` event for Sysmon or ETW. They would be easier to scale and integrate with enterprise tooling.

![Alt text](https://github.com/TheWover/donut/blob/master/ModuleMonitor/img/detected.png?raw=true "CLR Sentry detection")      

# Usage

```
| Module Monitor [v0.1]
| Copyright (c) 2019 TheWover

Usage: ModuleMonitor.exe [--clr-sentry]

```
