# ProcessManager

Has its own repo at: https://github.com/TheWover/ProcessManager

ps-like .NET Assembly for enumerating processes on the current machine or a remote machine (using current token). Has the unique feature of telling you whether each process is managed (has the CLR loaded). Compatible with .NET v3.5.

All enumeration is done with only built-in .NET APIs and PInvoke, rather than any third-party libraries or usage of WMI.

* PPID value of "-1" means that the parent is no longer running or is not accessible.
* Arch value of "*" means that the process could not be accessed or the architecture could not be determined. Usually a permissions issue.
* Managed value of "True" means that the CLR is loaded into the process. That is, it is a "managed" process because it is running .NET managed code.
* Integrity value of "Unknown" means exactly that.
* Blank User value means that the user information of the process could not be obtained.

**I have not tested ProcessManager's remote enumeration option. :-P Neither me nor Odzhan have a lab setup for testing that. Please feel free to let us know of any issues.**

![Alt text](https://github.com/TheWover/ProcessManager/blob/master/img/usage.JPG?raw=true "General Usage")

# Usage

```
| Process Manager [v0.2]  
| Copyright (c) 2019 TheWover

Usage: ProcessManager.exe [options] 

      -h, --help           Display this help menu. 
      --machine            Specify a machine to query. Machine name or IP Address may be used.
      --name               Filter by a process name.      
      
Examples:  

ProcessManager.exe
ProcessManager.exe --name svchost
ProcessManager.exe --machine workstation2  
ProcessManager.exe --machine 10.30.134.13 
```
