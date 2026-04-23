package memory

import (
	"encoding/json"
	"fmt"
	"net"
	"regexp"
	"unicode"
)

var (
	emailRegex     = regexp.MustCompile(`[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`)
	domainRegex    = regexp.MustCompile(`(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}`)
	ipv4Regex      = regexp.MustCompile(`\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b`)
	btcRegex       = regexp.MustCompile(`\b(1|3)[1-9A-HJ-NP-Za-km-z]{25,34}\b`)
	btcBech32Regex = regexp.MustCompile(`\bbc1[a-zA-Z0-9]{25,39}\b`)
	ethRegex       = regexp.MustCompile(`\b0x[a-fA-F0-9]{40}\b`)
	solRegex       = regexp.MustCompile(`\b[1-9A-HJ-NP-Za-km-z]{32,44}\b`)
	// Generic High Entropy API Key patterns
	// specific known patterns are in scanForSecrets, these are more generic
	apiKeyRegex = regexp.MustCompile(`(sk-[a-zA-Z0-9]{32,})|(ghp_[a-zA-Z0-9]{36})|(eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,})`)
)

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

		// Scan for patterns (Regex for Emails, IPs, Domains, API Keys, Wallets)
		if opts.ScanPatterns {
			emails, domains, ips, wallets, extraSecrets := scanForPatterns(data, region.Start)
			result.Emails = append(result.Emails, emails...)
			result.Domains = append(result.Domains, domains...)
			result.IPs = append(result.IPs, ips...)
			result.Wallets = append(result.Wallets, wallets...)
			result.Secrets = append(result.Secrets, extraSecrets...)

			// Scan for JSON
			jsons := scanForJSON(data)
			result.JSONs = append(result.JSONs, jsons...)
		}
	}

	// Deduplicate findings
	result.Emails = uniqueStrings(result.Emails)
	result.Domains = uniqueStrings(result.Domains)
	result.IPs = uniqueStrings(result.IPs)
	result.JSONs = uniqueStrings(result.JSONs)
	result.Strings = uniqueStrings(result.Strings)

	// Network connections
	if opts.ScanNetwork {
		conns, err := GetProcessNetwork(opts.PID)
		if err == nil {
			result.Network = conns
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

// scanForPatterns extracts regex based artifacts
func scanForPatterns(data []byte, baseOffset uint64) (emails []string, domains []string, ips []string, wallets []WalletMatch, secrets []SecretMatch) {
	// Emails
	emailMatches := emailRegex.FindAll(data, -1)
	for _, m := range emailMatches {
		if len(m) > 0 {
			emails = append(emails, string(m))
		}
	}

	// Domains
	domainMatches := domainRegex.FindAll(data, -1)
	for _, m := range domainMatches {
		if len(m) > 0 {
			domains = append(domains, string(m))
		}
	}

	// IPs
	ipMatches := ipv4Regex.FindAll(data, -1)
	for _, m := range ipMatches {
		if len(m) > 0 && net.ParseIP(string(m)) != nil {
			ips = append(ips, string(m))
		}
	}

	// Crypto Wallets
	// BTC
	btcMatches := btcRegex.FindAll(data, -1)
	for _, m := range btcMatches {
		if len(m) > 0 {
			wallets = append(wallets, WalletMatch{Type: "BTC", Address: string(m)})
		}
	}
	btcBech32Matches := btcBech32Regex.FindAll(data, -1)
	for _, m := range btcBech32Matches {
		if len(m) > 0 {
			wallets = append(wallets, WalletMatch{Type: "BTC", Address: string(m)})
		}
	}
	// ETH
	ethMatches := ethRegex.FindAll(data, -1)
	for _, m := range ethMatches {
		if len(m) > 0 {
			wallets = append(wallets, WalletMatch{Type: "ETH", Address: string(m)})
		}
	}
	// SOL
	solMatches := solRegex.FindAll(data, -1)
	for _, m := range solMatches {
		if len(m) > 0 {
			wallets = append(wallets, WalletMatch{Type: "SOL", Address: string(m)})
		}
	}

	// API Keys (High Entropy)
	apiKeyMatches := apiKeyRegex.FindAllIndex(data, -1)
	for _, loc := range apiKeyMatches {
		val := string(data[loc[0]:loc[1]])
		secrets = append(secrets, SecretMatch{
			Type:       "detected_api_key",
			Value:      maskSecret(val),
			Offset:     baseOffset + uint64(loc[0]),
			Confidence: 60, // Lower confidence for generic regex
		})
	}

	return
}

// scanForJSON tries to find and validate JSON objects
func scanForJSON(data []byte) []string {
	var found []string
	// Simple heuristic: look for { and } with some content in between
	// This is expensive if we parse everything, so we'll look for plausible start/ends

	startIdx := 0
	for {
		idx := findByte(data[startIdx:], '{')
		if idx == -1 {
			break
		}
		actualStart := startIdx + idx

		// Look for a matching closing brace within reasonable distance
		// We limit JSON object size to 4096 bytes for performance sanity in this scanner
		maxLen := 4096
		searchEnd := actualStart + maxLen
		if searchEnd > len(data) {
			searchEnd = len(data)
		}

		// We want the *last* } in the range to maximize chance of catching the full object if valid,
		// but standard JSON parser will just take what it needs.
		// Let's just try to parse from the bracket

		// Optimization: check if it looks like JSON before passing to decoder
		// e.g. next char is " or space/byte
		if actualStart+1 < len(data) {
			next := data[actualStart+1]
			if next != '"' && !unicode.IsSpace(rune(next)) && next != '}' {
				startIdx = actualStart + 1
				continue
			}
		}

		var js map[string]interface{}
		// Try to unmarshal a slice starting at actualStart
		// Unmarshal will decode until the end of the JSON values
		// However, Unmarshal expects the WHOLE slice to be valid JSON or it might error if it finds garbage after?
		// Actually Unmarshal just needs valid JSON. But if we pass a huge blob it might be slow.
		// Let's rely on a stricter heuristic: Find balanced brackets?
		// Standard Unmarshal is too greedy/lenient or requires exact bounds.

		// Alternative: Use json.Decoder which can read from a stream
		// But creating a reader for every byte is slow.

		// Heuristic: Extract a chunk up to the next '}' that balances?
		// Too complex for a quick scanner.
		// Let's searching for a closing brace that makes it valid.

		subData := data[actualStart:searchEnd]
		if json.Valid(subData) {
			found = append(found, string(subData))
			startIdx = searchEnd
			continue
		}

		// Try to find the closing brace
		balance := 0
		endFound := -1
		for i, b := range subData {
			if b == '{' {
				balance++
			} else if b == '}' {
				balance--
				if balance == 0 {
					endFound = i
					break
				}
			}
		}

		if endFound != -1 {
			potentialJSON := subData[:endFound+1]
			if json.Unmarshal(potentialJSON, &js) == nil {
				// It's valid JSON object
				// Filter out trivial empty ones {}
				if len(js) > 0 {
					// Re-marshal to compact string or just keep raw?
					// Let's keep raw but maybe compacted
					minified, _ := json.Marshal(js)
					found = append(found, string(minified))
				}
				startIdx = actualStart + endFound + 1
				continue
			}
		}

		startIdx = actualStart + 1
	}
	return found
}

func uniqueStrings(input []string) []string {
	keys := make(map[string]bool)
	list := []string{}
	for _, entry := range input {
		if _, value := keys[entry]; !value {
			keys[entry] = true
			list = append(list, entry)
		}
	}
	return list
}

func findByte(data []byte, b byte) int {
	for i, v := range data {
		if v == b {
			return i
		}
	}
	return -1
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
