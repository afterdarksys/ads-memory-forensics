package memory

// Region represents a memory region
type Region struct {
	Start      uint64 `json:"start"`
	End        uint64 `json:"end"`
	Size       uint64 `json:"size"`
	Readable   bool   `json:"readable"`
	Writable   bool   `json:"writable"`
	Executable bool   `json:"executable"`
	Type       string `json:"type"` // heap, stack, mapped, anonymous, etc.
	Path       string `json:"path,omitempty"`
}

// DumpResult represents the result of a memory dump
type DumpResult struct {
	PID         int32  `json:"pid"`
	ProcessName string `json:"process_name"`
	RegionCount int    `json:"region_count"`
	TotalSize   uint64 `json:"total_size"`
	OutputPath  string `json:"output_path,omitempty"`
}

// NetworkConnection represents an open network connection
type NetworkConnection struct {
	LocalAddr  string `json:"local_addr"`
	RemoteAddr string `json:"remote_addr"`
	State      string `json:"state"`
	Protocol   string `json:"protocol"` // TCP/UDP
	FD         int32  `json:"fd"`
}

// SecretMatch represents a found secret/credential
type SecretMatch struct {
	Type       string `json:"type"` // api_key, password, token, private_key, etc.
	Value      string `json:"value"`
	Offset     uint64 `json:"offset"`
	Confidence int    `json:"confidence"` // 0-100
}

// WalletMatch represents a potentially found crypto wallet address
type WalletMatch struct {
	Type    string `json:"type"` // BTC, ETH, SOL
	Address string `json:"address"`
}

// ScanOptions configures memory scanning
type ScanOptions struct {
	PID           int32  `json:"pid"`
	ScanSecrets   bool   `json:"scan_secrets"`
	ScanInjection bool   `json:"scan_injection"`
	ScanStrings   bool   `json:"scan_strings"`
	ScanPatterns  bool   `json:"scan_patterns"` // Enable regex for emails, IPs, etc.
	ScanNetwork   bool   `json:"scan_network"`
	YaraRulesPath string `json:"yara_rules_path,omitempty"`
}

// ScanResult represents memory scan results
type ScanResult struct {
	PID            int32               `json:"pid"`
	ProcessName    string              `json:"process_name"`
	BytesScanned   uint64              `json:"bytes_scanned"`
	RegionsScanned int                 `json:"regions_scanned"`
	Secrets        []SecretMatch       `json:"secrets,omitempty"`
	Injections     []InjectionMatch    `json:"injections,omitempty"`
	Strings        []string            `json:"strings,omitempty"`
	Emails         []string            `json:"emails,omitempty"`
	Domains        []string            `json:"domains,omitempty"`
	IPs            []string            `json:"ips,omitempty"`
	JSONs          []string            `json:"jsons,omitempty"`
	Wallets        []WalletMatch       `json:"wallets,omitempty"`
	Network        []NetworkConnection `json:"network,omitempty"`
	YaraMatches    []YaraMatch         `json:"yara_matches,omitempty"`
	ThreatScore    int                 `json:"threat_score"`
}

// InjectionMatch represents a code injection indicator
type InjectionMatch struct {
	Type        string `json:"type"` // shellcode, rop_chain, hook, etc.
	Offset      uint64 `json:"offset"`
	Size        int    `json:"size"`
	Description string `json:"description"`
	Signature   string `json:"signature,omitempty"`
}

// YaraMatch represents a YARA rule match
type YaraMatch struct {
	Rule    string   `json:"rule"`
	Offset  uint64   `json:"offset"`
	Strings []string `json:"strings"`
}
