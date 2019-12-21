# DonutTest

A simple C# shellcode remote injector to use in testing donut. It contains both x86 and x64 versions of the shellcode, determines the architecture of the target process, and then injects the appropriate version into that process with CreateRemoteThread. The shellcode must be Base64-encoded and dropped into the code as a string. This ensures that it can be run entirely from memory.

You may Base64-encode your shellcode and copy it to your clipboard with the PowerShell below:

```powershell
$filename = "C:\\Test\donut\\loader.bin"
[Convert]::ToBase64String([IO.File]::ReadAllBytes($filename)) | clip
```

```
Usage:

DonutTest.exe [PID]

If no PID is specified, then DonutTest will inject the shellcode into itself.
```