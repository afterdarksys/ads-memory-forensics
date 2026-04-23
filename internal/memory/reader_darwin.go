//go:build darwin

package memory

/*
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <stdlib.h>

// Get task port for a process
kern_return_t get_task_for_pid_wrapper(int pid, mach_port_t *task) {
    return task_for_pid(mach_task_self(), pid, task);
}

// Read memory from a task
kern_return_t read_memory(mach_port_t task, mach_vm_address_t address, mach_vm_size_t size, void *buffer, mach_vm_size_t *bytes_read) {
    return mach_vm_read_overwrite(task, address, size, (mach_vm_address_t)buffer, bytes_read);
}

// Get region info
kern_return_t get_region_info(mach_port_t task, mach_vm_address_t *address, mach_vm_size_t *size, vm_region_basic_info_data_64_t *info) {
    mach_msg_type_number_t count = VM_REGION_BASIC_INFO_COUNT_64;
    mach_port_t object_name;
    return mach_vm_region(task, address, size, VM_REGION_BASIC_INFO_64, (vm_region_info_t)info, &count, &object_name);
}
*/
import "C"

import (
	"fmt"
	"unsafe"
)

// ListRegions returns all memory regions for a process
func ListRegions(pid int32) ([]Region, error) {
	var task C.mach_port_t
	kr := C.get_task_for_pid_wrapper(C.int(pid), &task)
	if kr != C.KERN_SUCCESS {
		return nil, fmt.Errorf("task_for_pid failed: %d (requires root)", kr)
	}

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

const maxReadSize = 256 * 1024 * 1024 // 256MB

// ReadMemory reads memory from a process
func ReadMemory(pid int32, address uint64, size uint64) ([]byte, error) {
	if size == 0 || size > maxReadSize {
		return nil, fmt.Errorf("invalid region size: %d (max %d)", size, maxReadSize)
	}

	var task C.mach_port_t
	kr := C.get_task_for_pid_wrapper(C.int(pid), &task)
	if kr != C.KERN_SUCCESS {
		return nil, fmt.Errorf("task_for_pid failed: %d (requires root)", kr)
	}

	buffer := make([]byte, size)
	var bytesRead C.mach_vm_size_t

	kr = C.read_memory(task, C.mach_vm_address_t(address), C.mach_vm_size_t(size),
		unsafe.Pointer(&buffer[0]), &bytesRead)
	if kr != C.KERN_SUCCESS {
		return nil, fmt.Errorf("mach_vm_read failed: %d", kr)
	}

	return buffer[:bytesRead], nil
}
