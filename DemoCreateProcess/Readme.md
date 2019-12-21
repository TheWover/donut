# DemoCreateProcess

A simple C# program to use as a demo for testing shellcode. It takes two program names (such as notepad.exe,calc.exe) as parameters. You may generate shellcode for it using donut:

64-bit:

```
.\donut.exe .\DemoCreateProcess\bin\Release\DemoCreateProcess.dll -c TestClass -m RunProcess -p "notepad.exe calc.exe"
```

32-bit:

```
.\donut.exe -a 1 .\DemoCreateProcess\bin\Release\DemoCreateProcess.dll -c TestClass -m RunProcess -p "notepad.exe calc.exe" 
```