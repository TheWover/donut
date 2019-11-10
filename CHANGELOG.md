# Changelog
All notable changes to this project will be documented in this file.

## [0.9.3]

### Added

- The -e switch can be used to disable entropy and/or encryption.
- The -z switch can be used on Windows to specify compression.
- The -f switch is now used to specify the output format.
- On Windows, the base64 encoded string is copied to the clipboard.
- Unmanaged entrypoint can be run as a thread with -t option.
- The -n switch can be used to specify name of module for HTTP staging.
- Target/Host process for shellcode can be terminated with -x switch.
- Command line read by GetCommandLineA, GetCommandLineW, __getmainargs, __wgetmainargs, _acmdln, _wcmdln replaced for unmanaged EXE files.
- Arguments for DLL function can be passed in as ANSI with -w option. Default is UNICODE.

### Changed

- Command line is no longer parsed using semi-colon or comma as a token.
- Calling a DLL function only requires passing a command line.

### Removed

- XSL files are no longer supported.
- Code stub for calling DLL function with multiple arguments.