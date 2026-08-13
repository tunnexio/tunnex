; S6.5a — Windows NSIS installer hooks: register the Tunnex privilege helper as an
; auto-start SYSTEM service at install, remove it at uninstall. The installer is elevated
; (perMachine), so this is the Windows equivalent of the macOS .pkg postinstall: the helper
; is set up at INSTALL time (no first-Connect prompt), and Add/Remove Programs cleans it up
; (so no self-uninstall watchdog is needed on Windows — unlike macOS drag-to-Trash).
; UNSIGNED is fine: Windows SCM does not require Authenticode on user-mode service binaries.

!macro customInstall
  DetailPrint "Registering the Tunnex helper service..."
  ; Remove any prior instance first (a reinstall, or a leftover from manual testing) so
  ; `sc create` can't fail with "service already exists".
  nsExec::ExecToLog 'sc stop tunnex-helper'
  nsExec::ExecToLog 'sc delete tunnex-helper'
  ; The Go helper speaks the SCM control protocol (svc.Run), so it runs as a real service.
  nsExec::ExecToLog 'sc create tunnex-helper binPath= "$INSTDIR\resources\helper\tunnex-helper.exe" start= auto DisplayName= "Tunnex Helper"'
  ; sidtype=unrestricted so the service token carries its NT SERVICE\tunnex-helper SID.
  ; The WFP kill-switch (wireguard firewall) looks up the running service's SID to permit
  ; its own encrypted packets; without a service SID, arming fails "The specified group
  ; does not exist" and full-tunnel can't connect. (Confirmed live on the box.)
  nsExec::ExecToLog 'sc sidtype tunnex-helper unrestricted'
  ; Per-service environment (the SCM passes it to the service at start): trust the installed
  ; app dir for the helper's caller-auth + pin the named-pipe socket. REG_MULTI_SZ, \0-sep.
  nsExec::ExecToLog 'reg add "HKLM\SYSTEM\CurrentControlSet\Services\tunnex-helper" /v Environment /t REG_MULTI_SZ /d "TUNNEX_INSTALL_DIR=$INSTDIR\0TUNNEX_HELPER_SOCKET=\\.\pipe\tunnex-helper" /f'
  ; Restart-on-failure — parity with the macOS LaunchDaemon KeepAlive so a crashed helper
  ; comes back and its startup self-heal releases any stranded WFP kill-switch.
  nsExec::ExecToLog 'sc failure tunnex-helper reset= 0 actions= restart/5000/restart/5000/restart/5000'
  ; failureflag=1 so the restart actions ALSO fire when the service reports STOPPED with
  ; a non-zero exit (serveHelper error path) — not only on an uncontrolled crash. Without
  ; it the "restart on failure" policy is dead for our controlled error exit (review #5).
  nsExec::ExecToLog 'sc failureflag tunnex-helper 1'
  nsExec::ExecToLog 'sc start tunnex-helper'
!macroend

!macro customUnInstall
  DetailPrint "Removing the Tunnex helper service..."
  nsExec::ExecToLog 'sc stop tunnex-helper'
  Sleep 1000
  nsExec::ExecToLog 'sc delete tunnex-helper'
!macroend
