package scanner

import "github.com/afterdarksystems/ads-memory-forensics/internal/memory"

// Finding is the unified result type returned by all scanner implementations.
type Finding struct {
	Type       string `json:"type"`            // "secret", "injection", "string"
	SubType    string `json:"sub_type"`         // e.g. "aws_access_key", "x86_nop_sled"
	Offset     uint64 `json:"offset"`
	Value      string `json:"value,omitempty"` // masked for secrets; description for others
	Confidence int    `json:"confidence"`      // 0-100
	Size       int    `json:"size,omitempty"`  // matched byte count
}

// Interface is the contract for all memory scanner implementations.
type Interface interface {
	Scan(data []byte, region memory.Region) []Finding
}
