#Requires -RunAsAdministrator
# S6.5a bare-box path — register the Tunnex privilege helper as a Windows SCM service.
# The unsigned build has no NSIS installer here; this script is the elevated install
# the packaged installer will do at S6.5b. Run from inside the extracted app folder
# (next to Tunnex.exe). Unsigned services register fine — SCM enforces Authenticode
# only on kernel drivers.
$ErrorActionPreference = "Stop"
$AppDir = $PSScriptRoot
$Helper = Join-Path $AppDir "resources\helper\tunnex-helper.exe"
$Svc = "tunnex-helper"

if (-not (Test-Path $Helper)) { throw "helper not found at $Helper" }

Write-Host ">> (re)creating the $Svc service"
sc.exe stop $Svc 2>$null | Out-Null
sc.exe delete $Svc 2>$null | Out-Null
Start-Sleep -Milliseconds 500
sc.exe create $Svc binPath= "`"$Helper`"" start= auto DisplayName= "Tunnex Helper" | Out-Null

# sidtype=unrestricted so the service token carries its NT SERVICE\tunnex-helper SID —
# the WFP kill-switch permits the service's own encrypted packets by that SID; without it
# arming fails "The specified group does not exist" and full-tunnel can't connect.
sc.exe sidtype $Svc unrestricted | Out-Null

# Per-service environment (the SCM passes this to the service at start): trust the
# packaged app's dir for the helper's caller-auth, and pin the named-pipe socket.
$reg = "HKLM:\SYSTEM\CurrentControlSet\Services\$Svc"
New-ItemProperty -Path $reg -Name Environment -PropertyType MultiString -Force -Value @(
  "TUNNEX_INSTALL_DIR=$AppDir",
  "TUNNEX_HELPER_SOCKET=\\.\pipe\tunnex-helper"
) | Out-Null

# Restart-on-failure — parity with the macOS LaunchDaemon KeepAlive, so a crashed
# helper comes back and its startup self-heal releases any stranded WFP kill-switch.
sc.exe failure $Svc reset= 0 actions= restart/5000/restart/5000/restart/5000 | Out-Null
# failureflag=1 so the restart actions also fire on a STOPPED-with-nonzero-exit (our
# serveHelper error path), not only an uncontrolled crash (review #5).
sc.exe failureflag $Svc 1 | Out-Null

Write-Host ">> starting"
sc.exe start $Svc | Out-Null
Start-Sleep -Seconds 1
sc.exe query $Svc
Write-Host ">> installed. Launch Tunnex.exe and Connect."
