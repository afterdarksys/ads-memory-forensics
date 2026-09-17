//go:build darwin

package memory

/*
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <libproc.h>
#include <stdlib.h>

kern_return_t get_task_for_pid_wrapper(int pid, mach_port_t *task) {
	return task_for_pid(mach_task_self(), pid, task);
}

kern_return_t read_memory(mach_port_t task, mach_vm_address_t address, mach_vm_size_t size, void *buffer, mach_vm_size_t *bytes_read) {
	return mach_vm_read_overwrite(task, address, size, (mach_vm_address_t)buffer, bytes_read);
}

kern_return_t get_region_info(mach_port_t task, mach_vm_address_t *address, mach_vm_size_t *size, vm_region_basic_info_data_64_t *info) {
	mach_msg_type_number_t count = VM_REGION_BASIC_INFO_COUNT_64;
	mach_port_t object_name;
	return mach_vm_region(task, address, size, VM_REGION_BASIC_INFO_64, (vm_region_info_t)info, &count, &object_name);
}

int get_process_name(int pid, char *buf, int bufsize) {
	return proc_name(pid, buf, bufsize);
}

void release_task_port(mach_port_t task) {
	mach_port_deallocate(mach_task_self(), task);
}
*/
import "C"

import (
	"fmt"
	"log"
	"sync"
	"unsafe"
)

// maxRegionSize caps individual region reads to avoid OOM on pathological mappings.

// poolBufSize is the size of buffers held in bufPool.
const poolBufSize = 16 * 1024 * 1024 // 16 MB

// bufPool recycles 16 MB read buffers to reduce GC pressure during scanning.
var bufPool = sync.Pool{
	New: func() interface{} {
		b := make([]byte, poolBufSize)
		return &b
	},
}

// ListRegions returns all memory regions for a process.
func ListRegions(pid int32) ([]Region, error) {
	var task C.mach_port_t
	kr := C.get_task_for_pid_wrapper(C.int(pid), &task)
	if kr != C.KERN_SUCCESS {
		return nil, fmt.Errorf("task_for_pid failed: %d (requires root)", kr)
	}
	defer C.release_task_port(task) // Bug 1: release send right

	var regions []Region
	var address C.mach_vm_address_t = 0
	var size C.mach_vm_size_t
	var info C.vm_region_basic_info_data_64_t

	for {
		kr = C.get_region_info(task, &address, &size, &info)
		if kr != C.KERN_SUCCESS {
			break
		}

		region := Region{
			Start:      uint64(address),
			End:        uint64(address) + uint64(size),
			Size:       uint64(size),
			Readable:   info.protection&C.VM_PROT_READ != 0,
			Writable:   info.protection&C.VM_PROT_WRITE != 0,
			Executable: info.protection&C.VM_PROT_EXECUTE != 0,
			Type:       getRegionType(info),
		}
		regions = append(regions, region)

		address += size
	}

	return regions, nil
}

func getRegionType(info C.vm_region_basic_info_data_64_t) string {
	if info.shared != 0 {
		return "shared"
	}
	if info.reserved != 0 {
		return "reserved"
	}
	return "private"
}

// processName returns the OS-reported name for pid via proc_name(3).
func processName(pid int32) string {
	buf := make([]byte, C.PROC_PIDPATHINFO_MAXSIZE)
	n := C.get_process_name(C.int(pid), (*C.char)(unsafe.Pointer(&buf[0])), C.int(len(buf)))
	if n <= 0 {
		return fmt.Sprintf("pid_%d", pid)
	}
	return string(buf[:n])
}

// ReadMemory reads size bytes from address in pid's address space.
// For regions ≤ 16 MB it borrows a buffer from bufPool to reduce GC pressure.
func ReadMemory(pid int32, address uint64, size uint64) ([]byte, error) {
	if size == 0 || size > maxRegionSize || address > ^uint64(0)-size {
		return nil, fmt.Errorf("invalid memory read bounds")
	}
	var task C.mach_port_t
	kr := C.get_task_for_pid_wrapper(C.int(pid), &task)
	if kr != C.KERN_SUCCESS {
		return nil, fmt.Errorf("task_for_pid failed: %d (requires root)", kr)
	}
	defer C.release_task_port(task) // Bug 2: release send right

	var bytesRead C.mach_vm_size_t

	if size <= poolBufSize {
		bp := bufPool.Get().(*[]byte)
		defer bufPool.Put(bp)
		buf := *bp

		kr = C.read_memory(task, C.mach_vm_address_t(address), C.mach_vm_size_t(size),
			unsafe.Pointer(&buf[0]), &bytesRead)
		if kr != C.KERN_SUCCESS {
			return nil, fmt.Errorf("mach_vm_read failed: %d", kr)
		}
		if uint64(bytesRead) < size { // Bug 10: warn on partial reads
			log.Printf("ReadMemory: partial read at 0x%x: got %d of %d bytes", address, bytesRead, size)
		}
		// Copy out of pooled buffer before returning it.
		result := make([]byte, bytesRead)
		copy(result, buf[:bytesRead])
		return result, nil
	}

	// Oversized region: allocate directly.
	buffer := make([]byte, size)
	kr = C.read_memory(task, C.mach_vm_address_t(address), C.mach_vm_size_t(size),
		unsafe.Pointer(&buffer[0]), &bytesRead)
	if kr != C.KERN_SUCCESS {
		return nil, fmt.Errorf("mach_vm_read failed: %d", kr)
	}
	if uint64(bytesRead) < size {
		log.Printf("ReadMemory: partial read at 0x%x: got %d of %d bytes", address, bytesRead, size)
	}
	return buffer[:bytesRead], nil
}
