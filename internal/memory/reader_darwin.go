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
	"bytes"
	"fmt"
	"log"
	"os"
	"sync"
	"unsafe"
)

// maxRegionSize caps individual region reads to avoid OOM on pathological mappings.
const maxRegionSize = 256 * 1024 * 1024 // 256 MB

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

// DumpProcess dumps all readable memory regions to outputPath.
// If outputPath is empty, only statistics are collected.
func DumpProcess(pid int32, outputPath string, includeAll bool) (*DumpResult, error) {
	regions, err := ListRegions(pid)
	if err != nil {
		return nil, err
	}

	result := &DumpResult{
		PID:         pid,
		OutputPath:  outputPath,
		ProcessName: processName(pid), // Bug 7: use proc_name
	}

	// Bug 9: actually write to file when a path is provided
	var f *os.File
	if outputPath != "" {
		f, err = os.Create(outputPath)
		if err != nil {
			return nil, fmt.Errorf("create dump file: %w", err)
		}
		defer f.Close()
	}

	for _, region := range regions {
		if !region.Readable && !includeAll {
			continue
		}
		if region.Size > maxRegionSize { // Bug 8: skip oversized regions
			continue
		}

		data, err := ReadMemory(pid, region.Start, region.Size)
		if err != nil {
			continue
		}

		if f != nil {
			if _, err := f.Write(data); err != nil {
				return nil, fmt.Errorf("write dump: %w", err)
			}
		}

		result.RegionCount++
		result.TotalSize += uint64(len(data))
	}

	return result, nil
}

// ScanProcess scans process memory for artifacts.
func ScanProcess(opts ScanOptions) (*ScanResult, error) {
	regions, err := ListRegions(opts.PID)
	if err != nil {
		return nil, err
	}

	result := &ScanResult{
		PID:         opts.PID,
		ProcessName: processName(opts.PID), // Bug 7: use proc_name
	}

	for _, region := range regions {
		if !region.Readable {
			continue
		}
		if region.Size > maxRegionSize { // Bug 8: cap region size
			continue
		}

		result.RegionsScanned++
		result.BytesScanned += region.Size

		data, err := ReadMemory(opts.PID, region.Start, region.Size)
		if err != nil {
			continue
		}

		if opts.ScanSecrets {
			result.Secrets = append(result.Secrets, scanForSecrets(data, region.Start)...)
		}
		if opts.ScanInjection {
			result.Injections = append(result.Injections, scanForInjection(data, region)...)
		}
		if opts.ScanStrings {
			result.Strings = append(result.Strings, extractSuspiciousStrings(data)...)
		}
	}

	result.ThreatScore = calculateThreatScore(result)
	return result, nil
}

func scanForSecrets(data []byte, baseOffset uint64) []SecretMatch {
	var matches []SecretMatch

	patterns := []struct {
		name   string
		prefix []byte
		minLen int
		maxLen int
	}{
		{"aws_access_key", []byte("AKIA"), 20, 20},
		{"aws_secret_key", []byte("aws_secret_access_key"), 40, 50},
		{"github_token", []byte("ghp_"), 36, 40},
		{"github_token", []byte("gho_"), 36, 40},
		{"api_key", []byte("sk-"), 40, 60},
		{"bearer_token", []byte("Bearer "), 20, 500},
		{"basic_auth", []byte("Basic "), 10, 200},
		{"private_key", []byte("-----BEGIN"), 100, 5000},
		{"password", []byte("password="), 8, 100},
		{"password", []byte("passwd="), 8, 100},
	}

	for _, p := range patterns {
		offset := 0
		for {
			idx := bytes.Index(data[offset:], p.prefix) // Bug 3: use bytes.Index
			if idx == -1 {
				break
			}
			actualOffset := offset + idx

			endOffset := actualOffset + p.maxLen
			if endOffset > len(data) {
				endOffset = len(data)
			}

			value := extractSecret(data[actualOffset:endOffset])
			if len(value) >= p.minLen {
				matches = append(matches, SecretMatch{
					Type:       p.name,
					Value:      maskSecret(value),
					Offset:     baseOffset + uint64(actualOffset),
					Confidence: 70,
				})
			}

			offset = actualOffset + 1
		}
	}

	return matches
}

func scanForInjection(data []byte, region Region) []InjectionMatch {
	var matches []InjectionMatch

	shellcodePatterns := []struct {
		name    string
		pattern []byte
		desc    string
	}{
		{"x86_nop_sled", []byte{0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90}, "NOP sled detected"},
		{"x64_syscall", []byte{0x0f, 0x05}, "syscall instruction"},
		{"x86_int80", []byte{0xcd, 0x80}, "int 0x80 (Linux syscall)"},
		{"x64_execve", []byte{0x48, 0x31, 0xc0, 0x48, 0x89, 0xc2}, "Potential execve shellcode"},
	}

	for _, p := range shellcodePatterns {
		idx := bytes.Index(data, p.pattern) // Bug 3: use bytes.Index
		if idx == -1 {
			continue
		}
		if !region.Executable { // Bug 6: fix redundant condition
			continue
		}
		matches = append(matches, InjectionMatch{
			Type:        p.name,
			Offset:      region.Start + uint64(idx),
			Size:        len(p.pattern),
			Description: p.desc,
		})
	}

	return matches
}

// extractSuspiciousStrings finds all occurrences of each pattern, not just the first.
func extractSuspiciousStrings(data []byte) []string {
	var suspicious []string

	patterns := []string{
		"http://", "https://",
		"/bin/sh", "/bin/bash", "cmd.exe", "powershell",
		"curl ", "wget ", "nc ", "netcat",
		"base64 -d", "eval(",
	}

	for _, p := range patterns {
		pat := []byte(p)
		offset := 0
		for { // Bug 5: loop to find all occurrences, not just first
			idx := bytes.Index(data[offset:], pat)
			if idx == -1 {
				break
			}
			absIdx := offset + idx

			start := absIdx - 10
			if start < 0 {
				start = 0
			}
			end := absIdx + 100
			if end > len(data) {
				end = len(data)
			}

			str := extractPrintableString(data[start:end])
			if len(str) > 10 {
				suspicious = append(suspicious, str)
			}

			offset = absIdx + 1
		}
	}

	return suspicious
}

func calculateThreatScore(result *ScanResult) int {
	score := 0
	score += len(result.Secrets) * 15
	score += len(result.Injections) * 25
	score += len(result.Strings) * 5
	score += len(result.YaraMatches) * 20
	if score > 100 {
		score = 100
	}
	return score
}

func extractSecret(data []byte) string {
	var result []byte
	for _, b := range data {
		if b >= 32 && b < 127 && b != ' ' {
			result = append(result, b)
		} else {
			break
		}
	}
	return string(result)
}

func maskSecret(s string) string { // Bug 4: use **** not ...
	if len(s) <= 8 {
		return "****"
	}
	return s[:4] + "****" + s[len(s)-4:]
}

func extractPrintableString(data []byte) string {
	var result []byte
	for _, b := range data {
		if b >= 32 && b < 127 {
			result = append(result, b)
		} else if len(result) > 0 {
			break
		}
	}
	return string(result)
}
