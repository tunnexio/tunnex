//go:build linux

package k8snetprep

// Seams for the external end-to-end test (hostfacts_e2e_linux_test.go), which
// needs the hostposture package and so cannot live inside this one.

// SetProcSysForTest points the rp_filter read-back at a directory.
func (r *Reconciler) SetProcSysForTest(dir string) { r.procSys = dir }

// SetIPSetRunnerForTest replaces the gateway's own ipset runner.
func (r *Reconciler) SetIPSetRunnerForTest(run IPSetRunner) { r.runIPSet = run }

// SetSysModuleForTest points the ip_set module check at a directory.
func (r *HostFactsReader) SetSysModuleForTest(dir string) { r.sysModule = dir }

// SetProcNetForTest points the reader's ip_tables_names read at a directory.
func (r *HostFactsReader) SetProcNetForTest(dir string) { r.procNet = dir }

// SetProcNetForTest points the gateway's own ip_tables_names read at a directory.
func (r *Reconciler) SetProcNetForTest(dir string) { r.procNet = dir }
