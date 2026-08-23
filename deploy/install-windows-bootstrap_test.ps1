$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$repositoryRoot = Split-Path -Parent $PSScriptRoot
$launcher = Join-Path $PSScriptRoot "install.ps1"
$scratch = Join-Path ([System.IO.Path]::GetTempPath()) ("tunnex-windows-bootstrap-{0}" -f [Guid]::NewGuid())
New-Item -ItemType Directory -Path $scratch | Out-Null

function Assert-Contains([string]$Output, [string]$Expected) {
    if (-not $Output.Contains($Expected)) {
        throw "expected output to contain '$Expected'`n--- output ---`n$Output"
    }
}

try {
    $fakeInstaller = Join-Path $scratch "canonical-install.sh"
    Set-Content -LiteralPath $fakeInstaller -Encoding utf8 -Value @'
#!/bin/sh
printf '%s\n' 'CANONICAL_INSTALLER_REACHED'
'@

    $env:TUNNEX_TEST_WINDOWS = "1"
    $env:TUNNEX_TEST_BASH = "/bin/sh"
    $env:TUNNEX_TEST_INSTALLER_PATH = $fakeInstaller
    $env:TUNNEX_TEST_DOCKER_READY = "1"
    $env:TUNNEX_TEST_DOCKER_READY_AFTER_INSTALL = "0"
    $env:TUNNEX_TEST_WINGET = ""

    $existingOutput = (& $launcher *>&1 | Out-String)
    if ($existingOutput -notmatch "▀█▀ █ █ █▄ █ █▄ █\s+█▀▀ ▀▄▀") {
        throw "expected the two-colour Tunnex wordmark`n--- output ---`n$existingOutput"
    }
    Assert-Contains $existingOutput "Connect Everything. Trust Nothing."
    Assert-Contains $existingOutput "Docker Desktop, Compose v2, and Git Bash are ready."
    Assert-Contains $existingOutput "CANONICAL_INSTALLER_REACHED"

    $wingetLog = Join-Path $scratch "winget.log"
    $fakeWinget = Join-Path $scratch "winget"
    $fakeGitBash = Join-Path $scratch "Git/bin/bash.exe"
    Set-Content -LiteralPath $fakeWinget -Encoding utf8 -Value @"
#!/bin/sh
printf '%s\n' "`$*" >> '$wingetLog'
case " `$* " in
*' Git.Git '*)
  mkdir -p '$scratch/Git/bin'
  printf '%s\n' '#!/bin/sh' 'exec /bin/sh "`$@"' > '$fakeGitBash'
  chmod +x '$fakeGitBash'
  ;;
esac
"@
    & chmod +x $fakeWinget
    if ($LASTEXITCODE -ne 0) { throw "could not make fake winget executable" }

    $env:TUNNEX_TEST_DOCKER_READY = "0"
    $env:TUNNEX_TEST_DOCKER_READY_AFTER_INSTALL = "1"
    $env:TUNNEX_TEST_WINGET = $fakeWinget
    $freshOutput = (& $launcher *>&1 | Out-String)
    Assert-Contains $freshOutput "Installing Docker.DockerDesktop"
    Assert-Contains $freshOutput "CANONICAL_INSTALLER_REACHED"
    $wingetArguments = Get-Content -LiteralPath $wingetLog -Raw
    Assert-Contains $wingetArguments "install --exact --id Docker.DockerDesktop"

    $env:TUNNEX_TEST_DOCKER_READY = "1"
    $env:TUNNEX_TEST_DOCKER_READY_AFTER_INSTALL = "0"
    $env:TUNNEX_TEST_BASH = ""
    $env:TUNNEX_TEST_MISSING_EXECUTABLE = "bash"
    $env:ProgramFiles = $scratch
    $gitOutput = (& $launcher *>&1 | Out-String)
    Assert-Contains $gitOutput "Installing Git.Git"
    Assert-Contains $gitOutput "CANONICAL_INSTALLER_REACHED"
    $wingetArguments = Get-Content -LiteralPath $wingetLog -Raw
    Assert-Contains $wingetArguments "install --exact --id Git.Git"

    Write-Host "install windows bootstrap contract: PASS"
} finally {
    Remove-Item Env:TUNNEX_TEST_WINDOWS -ErrorAction SilentlyContinue
    Remove-Item Env:TUNNEX_TEST_BASH -ErrorAction SilentlyContinue
    Remove-Item Env:TUNNEX_TEST_INSTALLER_PATH -ErrorAction SilentlyContinue
    Remove-Item Env:TUNNEX_TEST_DOCKER_READY -ErrorAction SilentlyContinue
    Remove-Item Env:TUNNEX_TEST_DOCKER_READY_AFTER_INSTALL -ErrorAction SilentlyContinue
    Remove-Item Env:TUNNEX_TEST_WINGET -ErrorAction SilentlyContinue
    Remove-Item Env:TUNNEX_TEST_MISSING_EXECUTABLE -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $scratch -Recurse -Force -ErrorAction SilentlyContinue
}
