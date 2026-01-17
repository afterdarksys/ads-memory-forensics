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

// ReadMemory reads memory from a process
func ReadMemory(pid int32, address uint64, size uint64) ([]byte, error) {
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

// DumpProcess dumps all readable memory regions to a file
func DumpProcess(pid int32, outputPath string, includeAll bool) (*DumpResult, error) {
	regions, err := ListRegions(pid)
	if err != nil {
		return nil, err
	}

	result := &DumpResult{
		PID:        pid,
		OutputPath: outputPath,
	}

	// Get process name (placeholder - would use proc_name in full impl)
	result.ProcessName = fmt.Sprintf("pid_%d", pid)

	var totalSize uint64
	var regionCount int

	for _, region := range regions {
		// Skip non-readable unless includeAll
		if !region.Readable && !includeAll {
			continue
		}

		regionCount++
		totalSize += region.Size
	}

	result.RegionCount = regionCount
	result.TotalSize = totalSize

	// In full implementation, would write to outputPath here
	// For now, just return the stats

	return result, nil
}

// ScanProcess scans process memory for artifacts
func ScanProcess(opts ScanOptions) (*ScanResult, error) {
	regions, err := ListRegions(opts.PID)
	if err != nil {
		return nil, err
	}

	result := &ScanResult{
		PID:         opts.PID,
		ProcessName: fmt.Sprintf("pid_%d", opts.PID),
	}

	for _, region := range regions {
		if !region.Readable {
			continue
		}

		result.RegionsScanned++
		result.BytesScanned += region.Size

		// Read region memory
		data, err := ReadMemory(opts.PID, region.Start, region.Size)
		if err != nil {
			continue
		}

		// Scan for secrets
		if opts.ScanSecrets {
			secrets := scanForSecrets(data, region.Start)
			result.Secrets = append(result.Secrets, secrets...)
		}

		// Scan for injection
		if opts.ScanInjection {
			injections := scanForInjection(data, region)
			result.Injections = append(result.Injections, injections...)
		}

		// Extract strings
		if opts.ScanStrings {
			strings := extractSuspiciousStrings(data)
			result.Strings = append(result.Strings, strings...)
		}
	}

	// Calculate threat score
	result.ThreatScore = calculateThreatScore(result)

	return result, nil
}

// scanForSecrets searches for credentials in memory
func scanForSecrets(data []byte, baseOffset uint64) []SecretMatch {
	var matches []SecretMatch

	// Secret patterns to search for
	patterns := []struct {
		name    string
		prefix  []byte
		minLen  int
		maxLen  int
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
			idx := findBytes(data[offset:], p.prefix)
			if idx == -1 {
				break
			}
			actualOffset := offset + idx

			// Extract potential secret
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

// scanForInjection searches for code injection indicators
func scanForInjection(data []byte, region Region) []InjectionMatch {
	var matches []InjectionMatch

	// Look for shellcode patterns
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
		idx := findBytes(data, p.pattern)
		if idx != -1 {
			// Only flag if in executable region or writable+executable
			if region.Executable || (region.Writable && region.Executable) {
				matches = append(matches, InjectionMatch{
					Type:        p.name,
					Offset:      region.Start + uint64(idx),
					Size:        len(p.pattern),
					Description: p.desc,
				})
			}
		}
	}

	return matches
}

// extractSuspiciousStrings extracts potentially malicious strings
func extractSuspiciousStrings(data []byte) []string {
	var suspicious []string

	// Look for URLs, IPs, commands
	patterns := []string{
		"http://", "https://",
		"/bin/sh", "/bin/bash", "cmd.exe", "powershell",
		"curl ", "wget ", "nc ", "netcat",
		"base64 -d", "eval(",
	}

	for _, p := range patterns {
		idx := findBytes(data, []byte(p))
		if idx != -1 {
			// Extract surrounding context
			start := idx - 10
			if start < 0 {
				start = 0
			}
			end := idx + 100
			if end > len(data) {
				end = len(data)
			}

			str := extractPrintableString(data[start:end])
			if len(str) > 10 {
				suspicious = append(suspicious, str)
			}
		}
	}

	return suspicious
}

func calculateThreatScore(result *ScanResult) int {
	score := 0

	// Secrets found
	score += len(result.Secrets) * 15

	// Injection indicators
	score += len(result.Injections) * 25

	// Suspicious strings
	score += len(result.Strings) * 5

	// YARA matches
	score += len(result.YaraMatches) * 20

	if score > 100 {
		score = 100
	}

	return score
}

// Helper functions
func findBytes(data, pattern []byte) int {
	if len(pattern) == 0 {
		return 0
	}
	for i := 0; i <= len(data)-len(pattern); i++ {
		match := true
		for j := 0; j < len(pattern); j++ {
			if data[i+j] != pattern[j] {
				match = false
				break
			}
		}
		if match {
			return i
		}
	}
	return -1
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

func maskSecret(s string) string {
	if len(s) <= 8 {
		return "****"
	}
	return s[:4] + "..." + s[len(s)-4:]
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
