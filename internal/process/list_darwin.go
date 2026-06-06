//go:build darwin

package process

/*
#include <sys/sysctl.h>
#include <sys/types.h>
#include <stdlib.h>

// list_all_processes allocates and fills a kinfo_proc array via sysctl KERN_PROC_ALL.
// Caller must free() the returned pointer. Sets *count on success (>= 0) or error (< 0).
struct kinfo_proc *list_all_processes(int *count) {
	int mib[3] = {CTL_KERN, KERN_PROC, KERN_PROC_ALL};
	size_t size = 0;
	if (sysctl(mib, 3, NULL, &size, NULL, 0) < 0) { *count = -1; return NULL; }
	struct kinfo_proc *procs = (struct kinfo_proc *)malloc(size);
	if (!procs) { *count = -2; return NULL; }
	if (sysctl(mib, 3, procs, &size, NULL, 0) < 0) { free(procs); *count = -3; return NULL; }
	*count = (int)(size / sizeof(struct kinfo_proc));
	return procs;
}
*/
import "C"

import (
	"fmt"
	"log"
	"unsafe"
)

// List returns all running processes via sysctl KERN_PROC_ALL.
// Kernel task (PID 0) is excluded. Requires no special privileges.
func List() ([]Process, error) {
	var count C.int
	cprocs := C.list_all_processes(&count)
	if count < 0 {
		return nil, fmt.Errorf("sysctl KERN_PROC_ALL failed (code %d)", count)
	}
	defer C.free(unsafe.Pointer(cprocs))

	n := int(count)
	// Cast C array to a Go slice backed by the same memory.
	slice := (*[1 << 20]C.struct_kinfo_proc)(unsafe.Pointer(cprocs))[:n:n]

	result := make([]Process, 0, n)
	for i := range slice {
		p := &slice[i]
		pid := int32(p.kp_proc.p_pid)
		if pid == 0 {
			continue
		}
		ppid := int32(p.kp_eproc.e_ppid)

		// proc_name(3) gives the full name; p_comm is truncated to MAXCOMLEN (15 chars).
		name := Name(pid)
		if name == "" {
			name = C.GoString((*C.char)(unsafe.Pointer(&p.kp_proc.p_comm[0])))
		}
		if name == "" {
			log.Printf("process.List: no name for pid %d", pid)
		}

		result = append(result, Process{PID: pid, PPID: ppid, Name: name})
	}
	return result, nil
}
