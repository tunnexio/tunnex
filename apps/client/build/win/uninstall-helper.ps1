#Requires -RunAsAdministrator
# S6.5a bare-box path — remove the Tunnex helper service + residue check. DISCONNECT the
# tunnel first (a graceful Down removes the WFP filters + wintun adapter; "death =
# enforcement" means killing the service with a tunnel still up leaves the kill-switch
# armed until a restart self-heals or the dead-man fires).
$Svc = "tunnex-helper"

Write-Host ">> stop + delete the service"
sc.exe stop $Svc 2>$null | Out-Null
Start-Sleep -Seconds 1
sc.exe delete $Svc 2>$null | Out-Null
Remove-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$Svc" -Name Environment -ErrorAction SilentlyContinue

Write-Host ""
Write-Host "=== RESIDUE CHECK (all must be gone) ==="
$q = sc.exe query $Svc 2>&1 | Out-String
if ($q -match "1060") { Write-Host "  service: removed OK" } else { Write-Host "  service STILL PRESENT <-- FAIL"; Write-Host $q }

$adapters = Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object { $_.InterfaceDescription -match "Wintun" -or $_.Name -match "Tunnex|tunnex" }
if ($adapters) { $adapters | ForEach-Object { Write-Host "  wintun adapter STILL PRESENT: $($_.Name) <-- FAIL (was the tunnel disconnected first?)" } }
else { Write-Host "  wintun adapter: gone OK" }

# WFP filters are keyed to the helper's provider GUID and are removed on a graceful
# Down / startup self-heal. A lingering block here means the tunnel wasn't disconnected
# before uninstall — reinstall, connect, disconnect, then uninstall.
Write-Host "  (WFP filters clear on disconnect/self-heal; if networking is blocked, reboot self-heals)"
Write-Host ">> uninstall done. Also delete the extracted app folder."
