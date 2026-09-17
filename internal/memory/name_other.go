//go:build !darwin

package memory

import "fmt"

// PID remains an explicit identifier where native process naming is unavailable.
func processName(pid int32) string { return fmt.Sprintf("pid_%d", pid) }
