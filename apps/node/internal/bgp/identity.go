package bgp

// ProcessIdentity records cleanup duties, never authority to adopt a daemon.
// Every inode and PID identity is captured only from an owned child process.
type ProcessIdentity struct {
	Generation                   uint64
	BootID, Namespace, Directory string
	Stage                        string
	DirectoryFile                FileIdentity
	Files                        []NamedFileIdentity
	Children                     []ChildIdentity
	Supervisor                   ChildIdentity
}
type FileIdentity struct {
	Device, Inode uint64
	Mode          uint32
}
type NamedFileIdentity struct {
	Name string
	File FileIdentity
}
type ChildIdentity struct {
	Name       string
	PID        int
	StartTicks uint64
	Executable FileIdentity
}
