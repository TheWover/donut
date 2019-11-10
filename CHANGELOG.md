# Changelog
All notable changes to this project will be documented in this file.

## [0.9.3]

### Added

* The -e switch can be used to disable entropy and/or encryption. Options are: 1=disable, 2=generate random names, 3=generate random names + encrypt.
* The -z switch on Windows specifies compression of the file. Supported algorithms are LZNT1, Xpress and Xpress Huffman via the RtlCompressBuffer API. See donut.c!get_file_info.
* The -f switch specifies the output format. 
  binary, base64, c, ruby, python, powershell and hex stored in encode.c. Base64 strings are copied to the clipboard on Windows.
* The -t switch tells the loader to run unmanaged entrypoint for EXE as a thread. Attempts to replace exit-related API in Import Address Table with RtlExitUserThread.
* The -n switch can be used to specify name of module for HTTP staging.
* The -y switch is experimental and may be removed from future versions. It tells the loader to create a new thread and return to the caller.
* The -x switch can be used to specify how loader terminates. Useful if user wants to terminate the host process.
* If the user uses the -p switch to specify parameters for an unmanaged EXE file, the Command line read by GetCommandLineA, GetCommandLineW, __getmainargs, __wgetmainargs, _acmdln, _wcmdln, __argv and __wargv are replaced.
* The -w switch tells the loader not to convert parameters to UNICODE before passing to unmanaged DLL function.
* C# generator by n1xbyte: https://github.com/n1xbyte/donutCS
* Go generator by awgh https://github.com/Binject/go-donut

### Changed

* Command line is no longer parsed using semi-colon or comma as a token. The -p switch now accepts a string with all parameters enclosed in quotation marks. For .NET DLL/EXE, these are separated by the loader using CommandLineToArgvW. For unmanaged DLL, the string is passed to the DLL function without any modification.

### Removed

* XSL files are no longer supported.
* Code stub for calling DLL function with multiple arguments.
