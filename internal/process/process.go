package process

// Process represents a running macOS process.
type Process struct {
	PID  int32
	PPID int32
	Name string
}

// CSFlags are code-signing status bits returned by csops(2).
type CSFlags uint32

const (
	CSValid   CSFlags = 0x00000001 // process has a valid code signature
	CSAdhoc   CSFlags = 0x00000002 // ad-hoc signed (no identity)
	CSRuntime CSFlags = 0x00010000 // hardened runtime enabled
)
