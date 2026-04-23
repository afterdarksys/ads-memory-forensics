//go:build linux

package memory

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// ListRegions returns all memory regions for a process
func ListRegions(pid int32) ([]Region, error) {
	mapsPath := fmt.Sprintf("/proc/%d/maps", pid)
	file, err := os.Open(mapsPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open maps: %w", err)
	}
	defer file.Close()

	var regions []Region
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}

		// Parse address range: 00400000-00452000
		rangeParts := strings.Split(fields[0], "-")
		if len(rangeParts) != 2 {
			continue
		}

		start, err := strconv.ParseUint(rangeParts[0], 16, 64)
		if err != nil {
			continue
		}

		end, err := strconv.ParseUint(rangeParts[1], 16, 64)
		if err != nil {
			continue
		}

		// Parse permissions: r-xp
		perms := fields[1]
		readable := strings.Contains(perms, "r")
		writable := strings.Contains(perms, "w")
		executable := strings.Contains(perms, "x")
		// shared := strings.Contains(perms, "s")
		// private := strings.Contains(perms, "p")

		// Parse path/name if present
		path := ""
		if len(fields) > 5 {
			path = strings.Join(fields[5:], " ")
		}

		// Determine region type (simplified)
		regionType := "anonymous"
		if path != "" {
			if strings.HasPrefix(path, "[") && strings.HasSuffix(path, "]") {
				regionType = path[1 : len(path)-1] // heap, stack, vdso, etc.
			} else {
				regionType = "mapped_file"
			}
		}

		regions = append(regions, Region{
			Start:      start,
			End:        end,
			Size:       end - start,
			Readable:   readable,
			Writable:   writable,
			Executable: executable,
			Type:       regionType,
			Path:       path,
		})
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading maps: %w", err)
	}

	return regions, nil
}

const maxReadSize = 256 * 1024 * 1024 // 256MB

// ReadMemory reads memory from a process
func ReadMemory(pid int32, address uint64, size uint64) ([]byte, error) {
	if size == 0 || size > maxReadSize {
		return nil, fmt.Errorf("invalid region size: %d (max %d)", size, maxReadSize)
	}

	memPath := fmt.Sprintf("/proc/%d/mem", pid)
	file, err := os.Open(memPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open mem: %w", err)
	}
	defer file.Close()

	buffer := make([]byte, size)

	// Seek to the offset
	_, err = file.Seek(int64(address), 0)
	if err != nil {
		return nil, fmt.Errorf("seek failed: %w", err)
	}

	// Read exact bytes
	n, err := file.Read(buffer)
	if err != nil {
		// It's common to fail reading parts of memory even if mapped readable,
		// e.g. if the page is not resident or IO error.
		// Return partial read if we got anything
		if n > 0 {
			return buffer[:n], nil
		}
		return nil, fmt.Errorf("read failed: %w", err)
	}

	return buffer[:n], nil
}
