//go:build darwin

package process

/*
#include <libproc.h>
#include <sys/types.h>

// csops is declared in <sys/codesign.h> which is not always in the public SDK;
// the symbol is always present in libSystem.
extern int csops(pid_t pid, unsigned int ops, void *useraddr, size_t usersize);

#define CS_OPS_STATUS 0
*/
import "C"

import (
	"fmt"
	"unsafe"
)

// Name returns the process name for pid via proc_name(3).
// Returns an empty string on failure; callers should fall back to p_comm.
func Name(pid int32) string {
	buf := make([]byte, C.PROC_PIDPATHINFO_MAXSIZE)
	n := C.proc_name(C.int(pid), unsafe.Pointer(&buf[0]), C.uint32_t(len(buf)))
	if n <= 0 {
		return ""
	}
	return string(buf[:n])
}

// CodeSigningStatus returns the CS_OPS_STATUS flags for pid via csops(2).
func CodeSigningStatus(pid int32) (CSFlags, error) {
	var flags C.uint32_t
	ret := C.csops(C.pid_t(pid), C.CS_OPS_STATUS, unsafe.Pointer(&flags), C.size_t(unsafe.Sizeof(flags)))
	if ret != 0 {
		return 0, fmt.Errorf("csops(%d, CS_OPS_STATUS): %d", pid, ret)
	}
	return CSFlags(flags), nil
}
