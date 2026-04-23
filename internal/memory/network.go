package memory

// GetProcessNetwork returns network connections for a given PID
// This is a cross-platform wrapper that relies on OS-specific files
func GetProcessNetwork(pid int32) ([]NetworkConnection, error) {
	return getProcessNetwork(pid)
}

// OS-specific implementations will define getProcessNetwork(pid int32)
