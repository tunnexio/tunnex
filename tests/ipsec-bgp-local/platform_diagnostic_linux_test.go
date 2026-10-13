//go:build linux

package ipsec

import (
 "context"
 "os"
 "path/filepath"
 "strings"
 "testing"
 "time"
)

// This overlay-only test reads the existing managed daemon. It creates no daemon,
// attaches no controller receipt and never advertises capability.
func TestOwnedPlatformDiagnostic(t *testing.T) {
 if os.Getenv("TUNNEX_OWNED_PLATFORM_DIAGNOSTIC")!="1" {t.Skip("owned diagnostic opt-in")}
 ns,err:=os.Readlink("/proc/self/ns/net");if err!=nil {t.Fatal(err)}
 entries,err:=os.ReadDir("/proc");if err!=nil {t.Fatal(err)}
 pid:=""
 for _,entry:=range entries {
  name:=entry.Name();if name==""||name[0]<'0'||name[0]>'9' {continue}
  exe,e:=os.Readlink(filepath.Join("/proc",name,"exe"));if e!=nil||exe!=daemonExecutable {continue}
  dns,e:=os.Readlink(filepath.Join("/proc",name,"ns/net"));if e!=nil||dns!=ns {continue}
  env,e:=os.ReadFile(filepath.Join("/proc",name,"environ"));if e!=nil||!strings.Contains(string(env),"STRONGSWAN_CONF="+daemonRunDirectory+"/strongswan.conf\x00") {continue}
  if pid!="" {t.Fatal("multiple matching managed charon processes")};pid=name
 }
 if pid=="" {t.Fatal("existing managed charon absent")}
 alive:=func()bool {exe,e:=os.Readlink(filepath.Join("/proc",pid,"exe"));return e==nil&&exe==daemonExecutable}
 daemon,err:=NewDaemonClient(daemonRunDirectory+"/charon.vici");if err!=nil {t.Fatal(err)}
 ctx,cancel:=context.WithTimeout(context.Background(),30*time.Second);defer cancel()
 p,err:=newRuntimePlatformProbe("/sbin/ip","/usr/sbin/nft",daemon,alive);if err!=nil {t.Fatal("probe construction refused",err)}
 t.Log("OWNED_NAMESPACE",ns,"EXISTING_MANAGED_CHARON_PID",pid)
 inventory,e:=daemon.Inspect(ctx);if e==nil {t.Log("DAEMON_PROFILE",inventory.Version,inventory.Daemon,inventory.Plugins)}else {t.Log("DAEMON_INSPECTION_REFUSED",e)}
 steps:=[]struct{name string;call func(context.Context)error}{{"privilege",p.privilege},{"packaged",p.packaged},{"daemon",p.daemon},{"kernel",p.kernel},{"xfrm",p.xfrm},{"environment",p.environment},{"nft_check_only",p.nft}}
 for _,step:=range steps {t.Run(step.name,func(t *testing.T){if err:=step.call(ctx);err!=nil {t.Error("ACTUAL_PRODUCT_STEP_REFUSED",err)}})}
 // The actual exported product probe is read-only/check-only. Its receipt is
 // deliberately discarded; no qualification is attached to the running node.
 if _,err:=ProbeRuntimePlatform(ctx,"/sbin/ip","/usr/sbin/nft",daemon,alive);err!=nil {t.Log("ACTUAL_EXPORTED_PROBE_REFUSED",err)}else {t.Log("ACTUAL_EXPORTED_PROBE_PASSED_NO_RECEIPT_ATTACHED")}
}
