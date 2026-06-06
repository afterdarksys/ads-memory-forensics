package memory

// Reader is the interface for memory reading operations.
// The darwin implementation uses mach_vm_read; tests can inject a fake.
type Reader interface {
	ListRegions(pid int32) ([]Region, error)
	ReadMemory(pid int32, address uint64, size uint64) ([]byte, error)
}
