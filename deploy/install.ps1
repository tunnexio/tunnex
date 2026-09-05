# Tunnex Windows one-command launcher.
#
#   irm https://get.tunnex.io/install.ps1 | iex
#
# This file owns only Windows host preparation. Release selection, signature
# verification, configuration, installation, and health checks remain in the
# canonical POSIX installer used by every platform.
[CmdletBinding()]
param([switch]$UiPreview)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
$script:TestRuntimeInstalled = $false
$script:TemporaryInstaller = $null

function Test-TunnexMotion {
    return (-not [Console]::IsOutputRedirected -and $env:TERM -ne "dumb" -and
        -not (Test-Path Env:NO_COLOR) -and $env:TUNNEX_LOADER -ne "never")
}

function Write-TunnexWordmarkRow([string]$White, [string]$Red, [string]$Rgb) {
    if ((Test-Path Env:NO_COLOR) -or $env:TERM -eq "dumb" -or $env:TUNNEX_COLOR -eq "never") {
        Write-Host "  $White$Red"
    } else {
        Write-Host "  $White" -NoNewline -ForegroundColor White
        if (($env:COLORTERM -eq "truecolor" -or $env:COLORTERM -eq "24bit") -and
            -not [Console]::IsOutputRedirected) {
            $esc = [char]27
            Write-Host "${esc}[38;2;${Rgb}m${Red}${esc}[0m"
        } else {
            Write-Host $Red -ForegroundColor DarkRed
        }
    }
    if (Test-TunnexMotion) { Start-Sleep -Milliseconds 120 }
}

function Show-TunnexBrandSweep {
    if (-not (Test-TunnexMotion)) { return }
    for ($step = 0; $step -lt 12; $step++) {
        Write-Host "`r    " -NoNewline
        for ($cell = 0; $cell -lt 12; $cell++) {
            if ($cell -eq $step) {
                Write-Host "━━" -NoNewline -ForegroundColor Cyan
            } else {
                Write-Host "──" -NoNewline -ForegroundColor DarkGray
            }
        }
        Start-Sleep -Milliseconds 70
    }
    Write-Host "`r                            `r" -NoNewline
}

function Write-TunnexWordmark {
    Write-Host ""
    Write-Host "  TUNNEX / GUIDED SETUP" -ForegroundColor DarkGray
    Write-Host ""
    Write-TunnexWordmarkRow "▀█▀ █ █ █▄ █ █▄ █ " "█▀▀ ▀▄▀" "176;58;69"
    Write-TunnexWordmarkRow " █  █ █ █ ▀█ █ ▀█ " "█▀▀ ▄▀▄" "143;39;51"
    Write-TunnexWordmarkRow " ▀  ▀▀▀ ▀  ▀ ▀  ▀ " "▀▀▀ ▀ ▀" "110;21;32"
    Show-TunnexBrandSweep
    Write-Host "  Connect Everything. Trust Nothing." -ForegroundColor White
    Write-Host ""
    Write-Host "  ────────────────────────────────────────────" -ForegroundColor DarkGray
}

function Write-TunnexStage([int]$Step, [string]$Title, [int]$Total = 2) {
    Write-Host ""
    Write-Host "  " -NoNewline
    for ($index = 1; $index -le $Total; $index++) {
        if ($index -lt $Step) {
            Write-Host "━" -NoNewline -ForegroundColor Cyan
        } elseif ($index -eq $Step) {
            Write-Host "●" -NoNewline -ForegroundColor Red
        } else {
            Write-Host "─" -NoNewline -ForegroundColor DarkGray
        }
        if (Test-TunnexMotion) { Start-Sleep -Milliseconds 35 }
    }
    Write-Host "  [$Step/$Total] $Title" -ForegroundColor White
    Write-Host ""
}

function Write-TunnexInfo([string]$Message) {
    Write-Host "    · " -NoNewline -ForegroundColor DarkGray
    Write-Host $Message
}

function Write-TunnexSuccess([string]$Message) {
    Write-Host "    ✓ " -NoNewline -ForegroundColor Cyan
    Write-Host $Message
}

function Write-TunnexPlanStart {
    Write-Host ""
    Write-Host "    ╭─ " -NoNewline -ForegroundColor DarkGray
    Write-Host "QuickStart plan" -ForegroundColor White
}

function Write-TunnexPlanItem([string]$Label, [string]$Value) {
    Write-Host ("    │  {0,-18} " -f $Label) -NoNewline -ForegroundColor DarkGray
    Write-Host $Value
}

function Write-TunnexPlanEnd {
    Write-Host "    ╰─────────────────────────────────────────" -ForegroundColor DarkGray
}

# Only used by the offline demonstration; never performs a host operation.
function Show-TunnexPreviewActivity([string]$Title) {
    if (-not (Test-TunnexMotion)) {
        Write-TunnexInfo $Title
        return
    }
    try {
        foreach ($frame in @("⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏")) {
            Write-Host "`r    $frame " -NoNewline -ForegroundColor Cyan
            Write-Host $Title -NoNewline
            Start-Sleep -Milliseconds 100
        }
    } finally {
        Write-Host ("`r" + (' ' * ($Title.Length + 6)) + "`r") -NoNewline
    }
    Write-TunnexSuccess $Title
}

function Show-TunnexUiPreview {
    Write-Host ""
    Write-Host "    DESIGN PREVIEW" -NoNewline -ForegroundColor Cyan
    Write-Host "  ·  Sample data / no installation"
    Write-TunnexStage 1 "Checking this host" 5
    Show-TunnexPreviewActivity "Checking host requirements"
    Write-TunnexInfo "macOS / Windows · Portable control plane"
    Write-TunnexStage 2 "Selecting a verified Tunnex release" 5
    Show-TunnexPreviewActivity "Verifying release signature"
    Write-TunnexInfo "Signed release · Images pinned by digest (sample)"
    Write-TunnexStage 3 "Configuring your control plane" 5
    Write-TunnexPlanStart
    Write-TunnexPlanItem "Dashboard" "https://vpn.example.com"
    Write-TunnexPlanItem "Administrator" "owner@example.com"
    Write-TunnexPlanEnd
    Write-TunnexStage 4 "Reviewing the installation plan" 5
    Write-TunnexPlanStart
    Write-TunnexPlanItem "Mode" "QuickStart (recommended)"
    Write-TunnexPlanItem "Gateway" "Separate Linux host"
    Write-TunnexPlanItem "Changes" "UI preview only; no host changes"
    Write-TunnexPlanEnd
    Write-Host ""
    Write-Host "    › " -NoNewline -ForegroundColor Red
    Write-Host "Proceed with this installation? " -NoNewline
    Write-Host "Y / n" -ForegroundColor DarkGray
    Write-TunnexStage 5 "Installing and verifying Tunnex" 5
    Show-TunnexPreviewActivity "Pulling verified images"
    Show-TunnexPreviewActivity "Waiting for control-plane health"
    Write-Host ""
    Write-Host "  ╭─ " -NoNewline -ForegroundColor Cyan
    Write-Host "PREVIEW COMPLETE" -ForegroundColor White
    Write-Host "  │" -NoNewline -ForegroundColor Cyan
    Write-Host "  This was a simulation. Nothing was installed."
    Write-Host "  │" -NoNewline -ForegroundColor Cyan
    Write-Host "  Next" -NoNewline -ForegroundColor White
    Write-Host "  Dashboard → Sign in → Enroll gateway"
    Write-Host "  ╰───────────────────────────────────────────" -ForegroundColor Cyan
    Write-Host ""
}

function Show-TunnexWaiting([int]$Tick) {
    if ([Console]::IsOutputRedirected -or $env:TERM -eq "dumb" -or
        (Test-Path Env:NO_COLOR) -or $env:TUNNEX_LOADER -eq "never") { return }
    $frames = @("⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏")
    Write-Progress -Activity "Tunnex · Preparing Windows" -Status "$($frames[$Tick % $frames.Length]) Waiting for Docker Desktop — complete its first-run prompt"
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
    Write-TunnexInfo "Installing $PackageId with Windows Package Manager..."
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
    Write-TunnexInfo "Starting Docker Desktop..."
    Start-Process -FilePath $dockerDesktop | Out-Null
    $deadline = (Get-Date).AddMinutes(5)
    $tick = 0
    try {
        while ((Get-Date) -lt $deadline) {
            if (Test-DockerReady) { return }
            Show-TunnexWaiting $tick
            $tick++
            Start-Sleep -Seconds 3
        }
    } finally {
        Write-Progress -Activity "Tunnex · Preparing Windows" -Completed
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
    Write-TunnexInfo "Fetching the canonical signed-release installer..."
    Invoke-WebRequest -UseBasicParsing -Uri $installerUrl -OutFile $script:TemporaryInstaller
    return $script:TemporaryInstaller
}

Write-TunnexWordmark
if ($UiPreview) {
    Show-TunnexUiPreview
    return
}
Write-TunnexStage 1 "Preparing this Windows host"
Assert-SupportedWindowsHost
Ensure-DockerDesktop
$bash = Ensure-GitBash
Write-TunnexSuccess "Docker Desktop, Compose v2, and Git Bash are ready."

try {
    $installer = Resolve-CanonicalInstaller
    Write-TunnexStage 2 "Starting guided Tunnex onboarding"
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
