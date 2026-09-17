package memory

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func requireYara(t *testing.T) {
	t.Helper()
	for _, name := range []string{"yara", "yarac"} {
		if _, err := exec.LookPath(name); err != nil {
			t.Skip("real YARA engine not installed")
		}
	}
}

func TestYaraStarterRules(t *testing.T) {
	requireYara(t)
	s, err := newYaraScanner("builtin")
	if err != nil {
		t.Fatal(err)
	}
	defer s.close()
	for _, tc := range []struct{ data, rule string }{
		{"benign application memory", ""},
		{"EICAR-STANDARD-ANTIVIRUS-TEST-FILE", "AfterDark_EICAR_Test"},
		{"sekurlsa::logonpasswords", "AfterDark_Credential_Dumping_Commands"},
	} {
		matches, err := s.scan([]byte(tc.data), 0x1234)
		if err != nil {
			t.Fatal(err)
		}
		if tc.rule == "" {
			if len(matches) != 0 {
				t.Fatalf("benign matches: %v", matches)
			}
			continue
		}
		if len(matches) != 1 || matches[0].Rule != tc.rule || matches[0].Offset != 0x1234 || len(matches[0].Strings) != 0 {
			t.Fatalf("bad match: %+v", matches)
		}
		if _, err := os.Stat(filepath.Join(s.dir, "region.bin")); !os.IsNotExist(err) {
			t.Fatal("region dump retained")
		}
	}
	dir := s.dir
	s.close()
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatal("temporary directory retained")
	}
}

func TestYaraCustomAndInvalidRules(t *testing.T) {
	requireYara(t)
	source := filepath.Join(t.TempDir(), "custom.yar")
	if err := os.WriteFile(source, []byte(`rule Custom { strings: $a = "custom marker" condition: $a }`), 0600); err != nil {
		t.Fatal(err)
	}
	s, err := newYaraScanner(source)
	if err != nil {
		t.Fatal(err)
	}
	defer s.close()
	matches, err := s.scan([]byte("custom marker"), 0)
	if err != nil || len(matches) != 1 || matches[0].Rule != "Custom" {
		t.Fatalf("%v %v", matches, err)
	}
	if err := os.WriteFile(source, []byte("not a rule"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := newYaraScanner(source); err == nil {
		t.Fatal("accepted invalid rules")
	}
	if _, err := newYaraScanner(t.TempDir()); err == nil {
		t.Fatal("accepted directory")
	}
}

func TestRequestedYaraMissingEngineFailsBeforeMemoryAccess(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	if _, err := ScanProcess(ScanOptions{PID: -1, YaraRulesPath: "builtin"}); err == nil {
		t.Fatal("missing engine returned clean scan")
	}
}
