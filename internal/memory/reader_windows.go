//go:build windows

package memory

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os/exec"
	"strconv"
	"syscall"
	"time"
	"unsafe"
)

var kernel32 = syscall.NewLazyDLL("kernel32.dll")
var virtualQueryEx = kernel32.NewProc("VirtualQueryEx")
var readProcessMemory = kernel32.NewProc("ReadProcessMemory")

type memoryBasicInfo struct {
	BaseAddress, AllocationBase uintptr
	AllocationProtect           uint32
	RegionSize                  uintptr
	State, Protect, Type        uint32
}

func ListRegions(pid int32) ([]Region, error) {
	if pid <= 0 {
		return nil, fmt.Errorf("invalid PID")
	}
	handle, err := syscall.OpenProcess(0x0400, false, uint32(pid))
	if err != nil {
		return nil, err
	}
	defer syscall.CloseHandle(handle)
	regions := make([]Region, 0)
	var address uintptr
	for len(regions) < 65536 {
		var info memoryBasicInfo
		n, _, callErr := virtualQueryEx.Call(uintptr(handle), address, uintptr(unsafe.Pointer(&info)), unsafe.Sizeof(info))
		if n == 0 {
			if callErr == syscall.Errno(87) {
				return regions, nil
			}
			return nil, fmt.Errorf("VirtualQueryEx: %w", callErr)
		}
		next := info.BaseAddress + info.RegionSize
		if info.RegionSize == 0 || next <= address {
			return nil, fmt.Errorf("invalid memory region")
		}
		if info.State == 0x1000 {
			p := info.Protect & 0xff
			accessible := info.Protect&0x100 == 0 && p != 1
			regions = append(regions, Region{Start: uint64(info.BaseAddress), End: uint64(next), Size: uint64(info.RegionSize), Readable: accessible && p != 0 && p != 0x10, Writable: accessible && (p == 4 || p == 8 || p == 0x40 || p == 0x80), Executable: accessible && p >= 0x10, Type: fmt.Sprintf("0x%x", info.Type)})
		}
		address = next
	}
	return nil, fmt.Errorf("memory region limit exceeded")
}

func ReadMemory(pid int32, address, size uint64) ([]byte, error) {
	if pid <= 0 || size == 0 || size > 64<<20 || address+size < address || uint64(uintptr(address)) != address {
		return nil, fmt.Errorf("invalid memory read (maximum 64 MiB)")
	}
	handle, err := syscall.OpenProcess(0x0010, false, uint32(pid))
	if err != nil {
		return nil, err
	}
	defer syscall.CloseHandle(handle)
	data := make([]byte, int(size))
	var count uintptr
	ok, _, err := readProcessMemory.Call(uintptr(handle), uintptr(address), uintptr(unsafe.Pointer(&data[0])), uintptr(size), uintptr(unsafe.Pointer(&count)))
	if ok == 0 {
		return nil, fmt.Errorf("ReadProcessMemory: %w", err)
	}
	if count != uintptr(size) {
		return nil, fmt.Errorf("partial memory read")
	}
	return data, nil
}

func getProcessNetwork(pid int32) ([]NetworkConnection, error) {
	if pid <= 0 {
		return nil, fmt.Errorf("invalid PID")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	script := `$ErrorActionPreference='Stop'; $items=@(Get-NetTCPConnection | Where-Object {$_.OwningProcess -eq ` + strconv.Itoa(int(pid)) + `} | Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,State);ConvertTo-Json -InputObject $items -Compress`
	out, err := exec.CommandContext(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script).Output()
	if err != nil {
		return nil, err
	}
	var rows []struct {
		LocalAddress, RemoteAddress string
		LocalPort, RemotePort       int
		State                       json.RawMessage
	}
	if err := json.Unmarshal(out, &rows); err != nil {
		return nil, err
	}
	result := make([]NetworkConnection, 0, len(rows))
	for _, r := range rows {
		result = append(result, NetworkConnection{LocalAddr: net.JoinHostPort(r.LocalAddress, strconv.Itoa(r.LocalPort)), RemoteAddr: net.JoinHostPort(r.RemoteAddress, strconv.Itoa(r.RemotePort)), State: string(r.State), Protocol: "TCP"})
	}
	return result, nil
}
