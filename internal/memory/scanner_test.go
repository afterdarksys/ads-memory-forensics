package memory

import (
	"strings"
	"testing"
)

func TestMergedScannerMasksSecretsAndKeepsPatternDetection(t *testing.T) {
	secret := "ghp_" + strings.Repeat("a", 36)
	matches := scanForSecrets([]byte(secret), 0)
	if len(matches) == 0 || strings.Contains(matches[0].Value, secret) || !strings.Contains(matches[0].Value, "****") {
		t.Fatalf("secret was not detected and masked: %#v", matches)
	}
	emails, _, ips, _, _ := scanForPatterns([]byte("admin@example.com 192.0.2.15"), 0)
	if len(emails) != 1 || len(ips) != 1 {
		t.Fatal("existing pattern detection lost")
	}
	stringsFound := extractSuspiciousStrings([]byte("https://one.example/path\x00https://two.example/path"))
	if len(stringsFound) != 2 {
		t.Fatalf("expected both occurrences, got %v", stringsFound)
	}
}
