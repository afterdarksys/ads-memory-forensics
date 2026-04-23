package memory

import (
	"fmt"
	"os/exec"
	"strings"
)

func getProcessNetwork(pid int32) ([]NetworkConnection, error) {
	// usage: lsof -n -P -p <pid> -i
	cmd := exec.Command("lsof", "-n", "-P", "-p", fmt.Sprintf("%d", pid), "-i")
	out, err := cmd.Output()
	if err != nil {
		// If lsof isn't installed or fails (e.g. permissions), return error
		// Exit code 1 means no matches usually, which is not an error for us but
		// exec.Command returns error.
		if exitError, ok := err.(*exec.ExitError); ok {
			if exitError.ExitCode() == 1 {
				return []NetworkConnection{}, nil // No connections found
			}
		}
		return nil, fmt.Errorf("lsof failed: %w", err)
	}

	var conns []NetworkConnection
	lines := strings.Split(string(out), "\n")
	// Header: COMMAND   PID USER   FD   TYPE             DEVICE SIZE/OFF NODE NAME
	// Example: main      123 root   3u  IPv4 0x...      0t0  TCP 127.0.0.1:8080 (LISTEN)

	for i, line := range lines {
		if i == 0 {
			continue // skip header
		}
		if len(strings.TrimSpace(line)) == 0 {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 9 {
			continue // potentially partial line
		}

		// Field indices depend on exact output format, but usually:
		// FD is fields[3]
		// TYPE is fields[4]
		// PROTO is fields[7] (TCP/UDP)
		// NAME is fields[8] (addr)

		// This is brittle parsing, but lsof -F might be better.
		// For now simple parsing:

		fdStr := fields[3]
		proto := fields[7]     // TCP or UDP
		nameField := fields[8] // 127.0.0.1:5432->127.0.0.1:5433 or *:80

		state := ""
		if len(fields) > 9 {
			state = strings.Trim(fields[9], "()")
		}

		// Parse address
		// If "->" exists, it's a connection
		parts := strings.Split(nameField, "->")
		local := parts[0]
		remote := ""
		if len(parts) > 1 {
			remote = parts[1]
		}

		// cleanup FD (3u -> 3)
		var fd int32
		fmt.Sscanf(fdStr, "%d", &fd)

		conns = append(conns, NetworkConnection{
			LocalAddr:  local,
			RemoteAddr: remote,
			State:      state,
			Protocol:   proto,
			FD:         fd,
		})
	}

	return conns, nil
}
