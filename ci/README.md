# Donut MSVC CI

`build-test-msvc.ps1` builds Donut with MSVC for either `debug` or `release`.

Targets:

- `x86`: builds with `VsDevCmd -arch=x86` using `Makefile_x86.msvc`.
- `x64`: builds with `VsDevCmd -arch=amd64` using `Makefile.msvc`.
- `x84`: builds with `VsDevCmd -arch=amd64` using `Makefile.msvc` and generates dual-mode shellcode.
- `arm64`: builds with `VsDevCmd -arch=arm64` using `Makefile_arm64.msvc`.

Configurations:

- `debug`: compiles the debug loader, creates a small native test executable, asks `donut.exe` to generate `loader.bin` plus the debug-only `instance` file, and runs `loader.exe instance`.
- `release`: compiles the release target, creates the same native test executable, asks `donut.exe` to generate `loader.bin`, then runs `inject_local.exe loader.bin`.

Workflow shape:

- one GitHub Actions YAML drives every lane through a matrix of `runner`, `target`, and `configuration`
- there is no branch filter, so pushes on feature branches such as `arm64` still trigger the workflow
- ARM64 currently uses a build-only smoke test for `donut.exe`; runtime loader execution is skipped until Donut has a real ARM64 shellcode architecture in the generator

The ARM64 makefile looks for `lib\aplibarm64.lib`. If it is missing, it links `ci\aplib_stub.c` so non-aPLib flows can keep compiling while ARM64 support is being ported. `DONUT_COMPRESS_APLIB` intentionally returns `APLIB_ERROR` through the stub.

aPLib's public package documents C depacker sources, but Donut's generator also needs the packer entry points declared in `include\aplib.h`. For real ARM64 compression support, provide a native ARM64 library exporting those symbols as `lib\aplibarm64.lib`.
