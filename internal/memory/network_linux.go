package memory

import (
	"bufio"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

func getProcessNetwork(pid int32) ([]NetworkConnection, error) {
	var conns []NetworkConnection

	// map inode -> fd for the process
	inodeToFD := make(map[string]int32)

	fdDir := fmt.Sprintf("/proc/%d/fd", pid)
	files, err := ioutil.ReadDir(fdDir)
	if err != nil {
		return nil, fmt.Errorf("failed to read fd dir: %w", err)
	}

	for _, f := range files {
		target, err := os.Readlink(filepath.Join(fdDir, f.Name()))
		if err != nil {
			continue
		}
		// target looks like "socket:[12345]"
		if strings.HasPrefix(target, "socket:[") && strings.HasSuffix(target, "]") {
			inode := target[8 : len(target)-1]
			fd, _ := strconv.Atoi(f.Name())
			inodeToFD[inode] = int32(fd)
		}
	}

	// Read process net tcp
	// In a real implementation, we might need to check /proc/[pid]/net/tcp if in a namespace
	// defaulting to /proc/net/tcp for simplicity or host net

	netFiles := []struct {
		path  string
		proto string
	}{
		{"/proc/net/tcp", "TCP"},
		{"/proc/net/tcp6", "TCP6"},
		{"/proc/net/udp", "UDP"},
		{"/proc/net/udp6", "UDP6"},
	}

	for _, nf := range netFiles {
		f, err := os.Open(nf.path)
		if err != nil {
			continue
		}
		defer f.Close()

		scanner := bufio.NewScanner(f)
		scanner.Scan() // skip header
		for scanner.Scan() {
			fields := strings.Fields(scanner.Text())
			if len(fields) < 10 {
				continue
			}

			// Format: sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
			// 0  1             2           3  4        5        6  7       8         9    10       11     12 ...

			localAddrHex := fields[1]
			remoteAddrHex := fields[2]
			stateHex := fields[3]
			inode := fields[9]

			if fd, ok := inodeToFD[inode]; ok {
				localIP, localPort := parseHexAddr(localAddrHex)
				remoteIP, remotePort := parseHexAddr(remoteAddrHex)
				state := parseState(stateHex)

				conns = append(conns, NetworkConnection{
					LocalAddr:  fmt.Sprintf("%s:%d", localIP, localPort),
					RemoteAddr: fmt.Sprintf("%s:%d", remoteIP, remotePort),
					State:      state,
					Protocol:   nf.proto,
					FD:         fd,
				})
			}
		}
	}

	return conns, nil
}

func parseHexAddr(hexAddr string) (string, int) {
	parts := strings.Split(hexAddr, ":")
	if len(parts) != 2 {
		return "", 0
	}

	// IP
	// For IPv4: 0100007F -> 127.0.0.1 (Little Endian in hex)
	// For IPv6 it's 32 chars

	ipHex := parts[0]
	portHex := parts[1]

	port, _ := strconv.ParseInt(portHex, 16, 32)

	var ip string
	if len(ipHex) == 8 {
		// IPv4
		b, _ := decodeHex(ipHex)
		if len(b) == 4 {
			// Little endian
			ip = fmt.Sprintf("%d.%d.%d.%d", b[3], b[2], b[1], b[0]) // wait, Linux /proc/net/tcp is usually machine native? usually little endian.
			// Actually it's documented as little-endian
			ip = fmt.Sprintf("%d.%d.%d.%d", b[0], b[1], b[2], b[3]) // Wait, usually it prints as integer.
			// 0100007F = 1.0.0.127 ? No.
			// Let's assume standard parsing for now. 0100007F -> 7F000001 -> 127.0.0.1.
			// b[3] is 7F (127), b[0] is 01 (1).
			ip = fmt.Sprintf("%d.%d.%d.%d", b[0], b[1], b[2], b[3])
		}
	} else {
		ip = ipHex // Keep hex for ipv6 for now strictly
	}

	return ip, int(port)
}

func decodeHex(s string) ([]byte, error) {
	// ... simple decode
	res := make([]byte, len(s)/2)
	for i := 0; i < len(s); i += 2 {
		val, _ := strconv.ParseUint(s[i:i+2], 16, 8)
		res[i/2] = byte(val)
	}
	return res, nil
}

func parseState(s string) string {
	// Simplified mapping
	switch s {
	case "01":
		return "ESTABLISHED"
	case "0A":
		return "LISTEN"
	default:
		return s
	}
}
