# Tunnex Windows one-command launcher.
#
#   irm https://get.tunnex.io/install.ps1 | iex
#
# This file owns only Windows host preparation. Release selection, signature
# verification, configuration, installation, and health checks remain in the
# canonical POSIX installer used by every platform.
[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
$script:TestRuntimeInstalled = $false
$script:TemporaryInstaller = $null

function Write-TunnexWordmark {
    Write-Host ""
    Write-Host "  ▀█▀ █ █ █▄ █ █▄ █ " -NoNewline -ForegroundColor White
    Write-Host "█▀▀ ▀▄▀" -ForegroundColor Red
    Write-Host "   █  █ █ █ ▀█ █ ▀█ " -NoNewline -ForegroundColor White
    Write-Host "█▀▀ ▄▀▄" -ForegroundColor Red
    Write-Host "   ▀  ▀▀▀ ▀  ▀ ▀  ▀ " -NoNewline -ForegroundColor White
    Write-Host "▀▀▀ ▀ ▀" -ForegroundColor Red
    Write-Host "  Connect Everything. Trust Nothing." -ForegroundColor DarkGray
    Write-Host "  Self-hosted Zero Trust VPN" -ForegroundColor DarkGray
}

function Resolve-Executable([string]$Name, [string[]]$Candidates) {
    if (-not ($env:TUNNEX_TEST_WINDOWS -eq "1" -and $env:TUNNEX_TEST_MISSING_EXECUTABLE -eq $Name)) {
        $command = Get-Command $Name -ErrorAction SilentlyContinue
        if ($null -ne $command) {
            return $command.Source
        }
    }
    foreach ($candidate in $Candidates) {
        if ($candidate -and (Test-Path -LiteralPath $candidate)) {
            return $candidate
        }
    }
    return $null
}

function Test-DockerReady {
    if ($env:TUNNEX_TEST_WINDOWS -eq "1") {
        return ($env:TUNNEX_TEST_DOCKER_READY -eq "1" -or $script:TestRuntimeInstalled)
    }
    $docker = Resolve-Executable "docker" @(
        "$env:ProgramFiles\Docker\Docker\resources\bin\docker.exe"
    )
    if (-not $docker) { return $false }
    # Docker Desktop returns a non-zero exit while its first-run window is
    # open. That is expected readiness state, not a terminating PowerShell
    # error; restore the caller preference after probing it.
    $savedErrorActionPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = "Continue"
        & $docker info *> $null
        if ($LASTEXITCODE -ne 0) { return $false }
        & $docker compose version *> $null
        return ($LASTEXITCODE -eq 0)
    } finally {
        $ErrorActionPreference = $savedErrorActionPreference
    }
}

function Assert-SupportedWindowsHost {
    $recovery = @"
Windows Server cannot run the Tunnex Windows installer on this host.

Why: Tunnex on Windows uses Docker Desktop's Linux-container backend. Docker
Desktop is unsupported on Windows Server, and signing in cannot add the CPU
virtualization support required by its Linux VM.

Choose one of these paths:
  1. Recommended for this EC2 host: run the Linux Tunnex installer on a Linux VM.
  2. Windows test host: use Windows 10/11 with WSL 2 and hardware virtualization enabled.
  3. AWS nested VM: choose a nested-virtualization-capable instance and enable
     Nested virtualization before installing Docker Desktop.
"@
    if ($env:TUNNEX_TEST_WINDOWS -eq "1") {
        if ($env:TUNNEX_TEST_WINDOWS_SERVER -eq "1") {
            Write-Host ""
            Write-Host $recovery -ForegroundColor Yellow
            exit 1
        }
        return
    }
    $operatingSystem = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
    if ([int]$operatingSystem.ProductType -ne 1) {
        Write-Host ""
        Write-Host $recovery -ForegroundColor Yellow
        exit 1
    }
}

function Install-WingetPackage([string]$PackageId) {
    $wingetCandidates = @()
    if ($env:TUNNEX_TEST_WINDOWS -eq "1" -and $env:TUNNEX_TEST_WINGET) {
        $wingetCandidates += $env:TUNNEX_TEST_WINGET
    }
    $winget = Resolve-Executable "winget" $wingetCandidates
    if (-not $winget) {
        throw "Windows Package Manager (winget) is required for automatic setup. Install App Installer, then run the same Tunnex command again."
    }
    Write-Host ">> Installing $PackageId with Windows Package Manager..."
    & $winget install --exact --id $PackageId --accept-package-agreements --accept-source-agreements --silent
    if ($LASTEXITCODE -ne 0) {
        throw "winget could not install $PackageId. Correct the error above, then run the same Tunnex command again."
    }
    if ($env:TUNNEX_TEST_WINDOWS -eq "1" -and $env:TUNNEX_TEST_DOCKER_READY_AFTER_INSTALL -eq "1") {
        $script:TestRuntimeInstalled = $true
    }
}

function Ensure-DockerDesktop {
    if (Test-DockerReady) { return }

    $dockerDesktop = "$env:ProgramFiles\Docker\Docker\Docker Desktop.exe"
    if (-not (Test-Path -LiteralPath $dockerDesktop)) {
        Install-WingetPackage "Docker.DockerDesktop"
    }
    if ($env:TUNNEX_TEST_WINDOWS -eq "1") {
        if (-not (Test-DockerReady)) {
            throw "Docker Desktop test runtime did not become ready"
        }
        return
    }

    if (-not (Test-Path -LiteralPath $dockerDesktop)) {
        throw "Docker Desktop was installed but is not available yet. Restart Windows if requested, then run the same Tunnex command again."
    }
    Write-Host ">> Starting Docker Desktop..."
    Start-Process -FilePath $dockerDesktop | Out-Null
    $deadline = (Get-Date).AddMinutes(5)
    while ((Get-Date) -lt $deadline) {
        if (Test-DockerReady) { return }
        Start-Sleep -Seconds 3
    }
    throw "Docker Desktop needs its first-run setup completed. Finish the Docker Desktop prompt, then run the same Tunnex command again."
}

function Ensure-GitBash {
    $testCandidates = @()
    if ($env:TUNNEX_TEST_WINDOWS -eq "1" -and $env:TUNNEX_TEST_BASH) {
        $testCandidates += $env:TUNNEX_TEST_BASH
    }
    $candidates = $testCandidates + @(
        "$env:ProgramFiles\Git\bin\bash.exe",
        "$env:ProgramFiles\Git\usr\bin\bash.exe",
        "${env:ProgramFiles(x86)}\Git\bin\bash.exe"
    )
    $bash = Resolve-Executable "bash" $candidates
    if ($bash) { return $bash }

    Install-WingetPackage "Git.Git"
    $bash = Resolve-Executable "bash" $candidates
    if (-not $bash) {
        throw "Git for Windows was installed but Git Bash is not available yet. Open a new Administrator PowerShell and run the same Tunnex command again."
    }
    return $bash
}

function Resolve-CanonicalInstaller {
    if ($env:TUNNEX_TEST_WINDOWS -eq "1" -and $env:TUNNEX_TEST_INSTALLER_PATH) {
        return $env:TUNNEX_TEST_INSTALLER_PATH
    }
    if ($env:TUNNEX_INSTALL_SH_PATH) {
        if (-not (Test-Path -LiteralPath $env:TUNNEX_INSTALL_SH_PATH -PathType Leaf)) {
            throw "TUNNEX_INSTALL_SH_PATH does not point to a readable install.sh file."
        }
        return (Resolve-Path -LiteralPath $env:TUNNEX_INSTALL_SH_PATH).Path
    }
    $installerUrl = if ($env:TUNNEX_INSTALL_SH_URL) {
        $env:TUNNEX_INSTALL_SH_URL
    } else {
        "https://get.tunnex.io"
    }
    $script:TemporaryInstaller = Join-Path ([System.IO.Path]::GetTempPath()) ("tunnex-install-{0}.sh" -f [Guid]::NewGuid())
    Write-Host ">> Fetching the canonical signed-release installer..."
    Invoke-WebRequest -UseBasicParsing -Uri $installerUrl -OutFile $script:TemporaryInstaller
    return $script:TemporaryInstaller
}

Write-TunnexWordmark
Write-Host ""
Write-Host "[1/2] Preparing this Windows host" -ForegroundColor Red
Assert-SupportedWindowsHost
Ensure-DockerDesktop
$bash = Ensure-GitBash
Write-Host ">> Docker Desktop, Compose v2, and Git Bash are ready."

try {
    $installer = Resolve-CanonicalInstaller
    Write-Host ""
    Write-Host "[2/2] Starting guided Tunnex onboarding" -ForegroundColor Red
    $homeDirectory = if ($env:TUNNEX_TEST_WINDOWS -eq "1") { (Get-Location).Path } else { $env:USERPROFILE }
    Push-Location $homeDirectory
    try {
        & $bash $installer
        if ($LASTEXITCODE -ne 0) {
            throw "The Tunnex installer exited with code $LASTEXITCODE"
        }
    } finally {
        Pop-Location
    }
} finally {
    if ($script:TemporaryInstaller -and (Test-Path -LiteralPath $script:TemporaryInstaller)) {
        Remove-Item -LiteralPath $script:TemporaryInstaller -Force
    }
}
