# Changelog
All notable changes to this project will be documented in this file.

## [0.9.3]

### Added

* The -e switch can be used to disable entropy and/or encryption. Options are: 1=none, 2=generate random names, 3=generate random names + use symmetric encryption.
* The -z switch tells the builder to compress the input file. 1=none, 2=aPLib. On Windows, a further three algorithms are supported, which are 3=LZNT1, 4=Xpress and 5=Xpress Huffman.
* The -f switch specifies the output format for loader. 1=binary, 2=base64, 3=c, 4=ruby, 5=python, 6=powershell, 7=c# and 8=hex. On Windows, Base64 strings are copied to the clipboard.
* The -t switch tells the loader to run unmanaged entrypoint for EXE as a thread. This also attempts to intercept exit-related API in Import Address Table by replacing their pointers with the address of RtlExitUserThread.
* The -n switch can be used to specify name of module for HTTP staging. If entropy is enabled, this is generated randomly.
* The -s switch specifies the HTTP server to download module from.
* The -y switch tells loader to create a new thread for the loader and continues executing at a specific address or Original Entry Point (OEP). The address should be provided as a string in hexadecimal format.
* The -x switch can be used to specify how loader terminates. 1=exit thread, 2=exit process.
* The -p switch is used to specify parameters to .NET method, DLL function or command line for an unmanaged EXE file. Wrap multiple parameters inside quotations.
* The -w switch tells the loader to convert parameters to UNICODE before passing to unmanaged DLL function.
* C# generator by n1xbyte: https://github.com/n1xbyte/donutCS
* Go generator by awgh https://github.com/Binject/go-donut

### Changed

* Command line is no longer parsed using semi-colon or comma as a token. The -p switch now accepts a string with all parameters enclosed in quotation marks. For .NET DLL/EXE, these are separated by the loader using CommandLineToArgvW. For unmanaged DLL, the string is passed to the DLL function without any modification.
* The -u switch to specify URL for HTTP stager is replaced with -s switch to prepare for a DNS stager.
* The -f switch to specify input file is now used to specify output format of loader.

### Removed

* XSL files are no longer supported.
* Code stub for calling DLL function with multiple arguments.
