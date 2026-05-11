[CmdletBinding()]
param(
  [ValidateSet("x86", "x64", "x84", "arm64")]
  [string]$Target = "x64",

  [ValidateSet("debug", "release")]
  [string]$Configuration = "debug",

  [switch]$SkipRun
)

$ErrorActionPreference = "Stop"

$RepoRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
$OutDir = Join-Path $RepoRoot "ci\out\$Target\$Configuration"
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
Set-Location $RepoRoot

function Get-VsDevCmd {
  $vswhere = Join-Path ${env:ProgramFiles(x86)} "Microsoft Visual Studio\Installer\vswhere.exe"
  if (-not (Test-Path $vswhere)) {
    throw "vswhere.exe was not found at $vswhere"
  }

  $installPath = & $vswhere -latest -products * -property installationPath
  if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($installPath)) {
    throw "Unable to locate a Visual Studio installation with MSVC tools"
  }

  $vsDevCmd = Join-Path $installPath "Common7\Tools\VsDevCmd.bat"
  if (-not (Test-Path $vsDevCmd)) {
    throw "VsDevCmd.bat was not found at $vsDevCmd"
  }

  return $vsDevCmd
}

function Invoke-StdInFile {
  param(
    [Parameter(Mandatory = $true)][string]$Command,
    [Parameter(Mandatory = $true)][string]$Content
  )

  $stdinFile = Join-Path $RepoRoot "ci\stdin.txt"
  Set-Content -Path $stdinFile -Value $Content -NoNewline
  try {
    & cmd.exe /s /c "$Command < `"$stdinFile`""
    if ($LASTEXITCODE -ne 0) {
      throw "Command failed with exit code $LASTEXITCODE`: $Command"
    }
  } finally {
    Remove-Item -Force -ErrorAction SilentlyContinue $stdinFile
  }
}

function Invoke-VsDevCmd {
  param(
    [Parameter(Mandatory = $true)][string]$Arch,
    [Parameter(Mandatory = $true)][string]$Command
  )

  $vsDevCmd = Get-VsDevCmd
  $cmdLine = "`"$vsDevCmd`" -no_logo -arch=$Arch && $Command"
  Write-Host ">> $cmdLine"
  & cmd.exe /s /c $cmdLine
  if ($LASTEXITCODE -ne 0) {
    throw "Command failed with exit code $LASTEXITCODE`: $Command"
  }
}

$matrix = @{
  x86 = @{
    VsArch = "x86"
    Makefile = "Makefile_x86.msvc"
    DonutArch = "1"
    RunDebugInstance = $true
    RunReleaseLoader = $true
    SmokeTestDonutExe = $true
  }
  x64 = @{
    VsArch = "amd64"
    Makefile = "Makefile.msvc"
    DonutArch = "2"
    RunDebugInstance = $true
    RunReleaseLoader = $true
    SmokeTestDonutExe = $true
  }
  x84 = @{
    VsArch = "amd64"
    Makefile = "Makefile.msvc"
    DonutArch = "3"
    RunDebugInstance = $true
    RunReleaseLoader = $true
    SmokeTestDonutExe = $true
  }
  arm64 = @{
    VsArch = "arm64"
    Makefile = "Makefile_arm64.msvc"
    DonutArch = "4"
    RunDebugInstance = $true
    RunReleaseLoader = $true
    SmokeTestDonutExe = $true
  }
}

$cfg = $matrix[$Target]
$makeTarget = if ($Configuration -eq "debug") { "debug" } else { "donut" }

# Fail before touching generated files if the requested MSVC environment is not
# available. The CI runner has a clean checkout; local runs often do not.
Get-VsDevCmd | Out-Null

Remove-Item -Force -ErrorAction SilentlyContinue `
  "instance", "loader.bin", "loader.exe", "inject_local.exe", "donut.exe", "donut_payload_ok.txt", `
  (Join-Path $OutDir "hello.exe"), (Join-Path $OutDir "loader.bin"), (Join-Path $OutDir "instance"), `
  (Join-Path $OutDir "donut_payload_ok.txt")

Invoke-VsDevCmd -Arch $cfg.VsArch -Command "nmake /nologo /f $($cfg.Makefile) $makeTarget"

$helloExe = Join-Path $OutDir "hello.exe"
Invoke-VsDevCmd -Arch $cfg.VsArch -Command "cl /nologo /W4 /WX /MT /O1 /Fe:`"$helloExe`" ci\hello.c"

$loaderBin = Join-Path $OutDir "loader.bin"
Invoke-VsDevCmd -Arch $cfg.VsArch -Command ".\donut.exe -a $($cfg.DonutArch) -b 1 -e 1 -z 1 -x 1 -i `"$helloExe`" -o `"$loaderBin`""

if ($Configuration -eq "debug") {
  if (-not (Test-Path "instance")) {
    throw "donut.exe did not create the debug instance file"
  }

  Copy-Item -Force "instance" (Join-Path $OutDir "instance")
}

if ($SkipRun) {
  Write-Host "Skipping loader.exe instance execution."
  exit 0
}

if ($Configuration -eq "debug") {
  if (-not $cfg.RunDebugInstance) {
    Write-Host "Skipping debug runtime execution."
    exit 0
  }

  & cmd.exe /s /c "echo. | loader.exe instance"
  if ($LASTEXITCODE -ne 0) {
    throw "loader.exe instance failed with exit code $LASTEXITCODE"
  }
} else {
  if (-not $cfg.RunReleaseLoader) {
    Write-Host "Skipping release runtime execution."
    exit 0
  }

  Invoke-StdInFile -Command "inject_local.exe `"$loaderBin`"" -Content "`r`n`r`n"
}

if (-not (Test-Path "donut_payload_ok.txt")) {
  throw "The test payload marker file was not created"
}

Move-Item -Force "donut_payload_ok.txt" (Join-Path $OutDir "donut_payload_ok.txt")
Write-Host "Donut $Target $Configuration smoke test passed."
