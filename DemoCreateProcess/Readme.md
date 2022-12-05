# DemoCreateProcess

A simple C# program to use as a demo for testing shellcode. It takes two program names (such as notepad.exe,calc.exe) as parameters. You may generate shellcode for it using donut:

64-bit:

```
.\donut.exe -i .\DemoCreateProcess\bin\Release\DemoCreateProcess.dll -c TestClass -m RunProcess -p "notepad.exe calc.exe"
```

32-bit:

```
.\donut.exe -i -a 1 .\DemoCreateProcess\bin\Release\DemoCreateProcess.dll -c TestClass -m RunProcess -p "notepad.exe calc.exe" 
```

# Building on Linux

This project can be built on Linux using Mono and xbuild. First, follow the official [instructions](https://www.mono-project.com/download/stable/#download-lin) for install Mono. Then, install `mono-xbuild`.

To build the project, simply `cd` to its root directory and run:

```
xbuild
```

To build in Release mode, run:

```
xbuild /p:Configuration=Release
```

If receiving errors about missing dependencies, try specifying the targeted .NET version:

```
xbuild /p:TargetFrameworkVersion="v4.5"
```

Once the project has been successfully built, the output DLL may be used as input to the Donut shellcode generator.
