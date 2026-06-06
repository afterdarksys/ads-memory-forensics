package scanner

import (
	"bytes"
	"math"

	"github.com/afterdarksystems/ads-memory-forensics/internal/memory"
)

const (
	entropyWindowSize    = 32
	highEntropyThreshold = 7.0 // bits — signals encrypted/compressed data
)

var secretPatterns = []struct {
	name       string
	prefix     []byte
	minLen     int
	maxLen     int
	confidence int
}{
	{"aws_access_key", []byte("AKIA"), 20, 20, 90},
	{"aws_secret_key", []byte("aws_secret_access_key"), 40, 50, 85},
	{"github_token", []byte("ghp_"), 36, 40, 85},
	{"github_token", []byte("gho_"), 36, 40, 85},
	{"api_key", []byte("sk-"), 40, 60, 60},
	{"bearer_token", []byte("Bearer "), 20, 500, 50},
	{"basic_auth", []byte("Basic "), 10, 200, 45},
	{"private_key", []byte("-----BEGIN"), 100, 5000, 90},
	{"password", []byte("password="), 8, 100, 40},
	{"password", []byte("passwd="), 8, 100, 40},
}

// SecretsScanner detects credentials and high-entropy blobs in memory.
type SecretsScanner struct{}

var _ Interface = (*SecretsScanner)(nil)

func (s *SecretsScanner) Scan(data []byte, region memory.Region) []Finding {
	findings := scanPatterns(data, region.Start)
	// Entropy scan only on anonymous RW (heap/stack) regions (D18 pre-filter).
	// Skipping RX (code) and file-backed regions eliminates most false positives.
	if isAnonymousRW(region) && len(data) >= entropyWindowSize {
		findings = append(findings, scanHighEntropy(data, region.Start)...)
	}
	return findings
}

// isAnonymousRW returns true for private, read-write, non-executable regions
// with no backing file — i.e. heap and stack pages.
func isAnonymousRW(region memory.Region) bool {
	return region.Readable && region.Writable && !region.Executable && region.Path == ""
}

func scanPatterns(data []byte, baseOffset uint64) []Finding {
	var findings []Finding
	for _, p := range secretPatterns {
		offset := 0
		for {
			idx := bytes.Index(data[offset:], p.prefix)
			if idx == -1 {
				break
			}
			abs := offset + idx
			end := abs + p.maxLen
			if end > len(data) {
				end = len(data)
			}
			value := extractSecret(data[abs:end])
			if len(value) >= p.minLen {
				findings = append(findings, Finding{
					Type:       "secret",
					SubType:    p.name,
					Offset:     baseOffset + uint64(abs),
					Value:      maskSecret(value),
					Confidence: p.confidence,
					Size:       len(value),
				})
			}
			offset = abs + 1
		}
	}
	return findings
}

// scanHighEntropy emits one Finding per contiguous run of high-entropy bytes.
func scanHighEntropy(data []byte, baseOffset uint64) []Finding {
	var findings []Finding
	var re rollingEntropy
	inRun := false
	runStart := 0

	for i, b := range data {
		re.push(b)
		if !re.full {
			continue
		}
		if re.entropy() >= highEntropyThreshold {
			if !inRun {
				inRun = true
				runStart = i - entropyWindowSize + 1
			}
		} else if inRun {
			inRun = false
			findings = append(findings, Finding{
				Type:       "secret",
				SubType:    "high_entropy_region",
				Offset:     baseOffset + uint64(runStart),
				Size:       i - runStart,
				Confidence: 55,
			})
		}
	}
	if inRun {
		findings = append(findings, Finding{
			Type:       "secret",
			SubType:    "high_entropy_region",
			Offset:     baseOffset + uint64(runStart),
			Size:       len(data) - runStart,
			Confidence: 55,
		})
	}
	return findings
}

// rollingEntropy computes Shannon entropy over a sliding window of entropyWindowSize bytes.
// Once the window is full, each push is O(1) amortized (D13).
type rollingEntropy struct {
	ring [entropyWindowSize]byte
	freq [256]int
	pos  int
	full bool
	h    float64
}

func (r *rollingEntropy) push(b byte) {
	if r.full {
		out := r.ring[r.pos]
		// Remove outgoing byte's contribution, add incoming byte's contribution.
		r.h -= entropyContrib(r.freq[out], entropyWindowSize)
		r.freq[out]--
		r.h += entropyContrib(r.freq[out], entropyWindowSize)

		r.h -= entropyContrib(r.freq[b], entropyWindowSize)
		r.freq[b]++
		r.h += entropyContrib(r.freq[b], entropyWindowSize)
	} else {
		// Window filling: recompute from scratch (O(256), only during first 32 bytes).
		r.freq[b]++
		wsize := r.pos + 1
		r.h = 0
		for i, c := range r.freq {
			r.h += entropyContrib(c, wsize)
			_ = i
		}
	}
	r.ring[r.pos] = b
	r.pos++
	if r.pos == entropyWindowSize {
		r.pos = 0
		r.full = true
	}
}

func (r *rollingEntropy) entropy() float64 { return r.h }

// entropyContrib returns -p*log2(p) for byte frequency c in a window of total bytes.
func entropyContrib(c, total int) float64 {
	if c <= 0 || total <= 0 {
		return 0
	}
	p := float64(c) / float64(total)
	return -p * math.Log2(p)
}

func extractSecret(data []byte) string {
	result := make([]byte, 0, 64)
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
	return s[:4] + "****" + s[len(s)-4:]
}
