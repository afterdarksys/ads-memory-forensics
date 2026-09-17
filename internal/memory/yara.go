package memory

import (
	"bytes"
	"context"
	_ "embed"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

//go:embed starter.yar
var starterRules []byte

// YARA runs in a separate process. Dumps live only in a private temporary
// directory and are removed after each region, including on engine failure.
type yaraScanner struct{ dir, engine, rules string }

func newYaraScanner(source string) (*yaraScanner, error) {
	engine, err := exec.LookPath("yara")
	if err != nil {
		return nil, fmt.Errorf("YARA requested: install yara and yarac: %w", err)
	}
	compiler, err := exec.LookPath("yarac")
	if err != nil {
		return nil, fmt.Errorf("YARA compiler unavailable: %w", err)
	}
	dir, err := os.MkdirTemp("", "ads-yara-")
	if err != nil {
		return nil, err
	}
	s := &yaraScanner{dir: dir, engine: engine, rules: filepath.Join(dir, "rules.compiled")}
	fail := func(err error) (*yaraScanner, error) { s.close(); return nil, err }
	if source == "builtin" {
		source = filepath.Join(dir, "starter.yar")
		if err := os.WriteFile(source, starterRules, 0600); err != nil {
			return fail(err)
		}
	} else {
		source, err = filepath.Abs(source)
		if err != nil {
			return fail(err)
		}
		info, err := os.Stat(source)
		if err != nil {
			return fail(err)
		}
		if !info.Mode().IsRegular() || info.Size() > 4*1024*1024 {
			return fail(fmt.Errorf("YARA source must be a regular file no larger than 4 MiB"))
		}
	}
	if _, err := runYara(compiler, source, s.rules); err != nil {
		return fail(fmt.Errorf("compile YARA rules: %w", err))
	}
	return s, nil
}

func (s *yaraScanner) close() { _ = os.RemoveAll(s.dir) }

var yaraIdentifier = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]*$`)

func (s *yaraScanner) scan(data []byte, regionStart uint64) ([]YaraMatch, error) {
	target := filepath.Join(s.dir, "region.bin")
	if err := os.WriteFile(target, data, 0600); err != nil {
		return nil, err
	}
	defer os.Remove(target)
	// Do not print matched strings: they may contain credentials. The reported
	// offset is the region base, not an invented individual string offset.
	output, err := runYara(s.engine, "-q", "-C", "-a", "10", s.rules, target)
	if err != nil {
		return nil, err
	}
	var matches []YaraMatch
	for _, line := range strings.Split(strings.TrimSpace(string(output)), "\n") {
		if line == "" {
			continue
		}
		rule, suffix, ok := strings.Cut(line, " ")
		if !ok || suffix != target || !yaraIdentifier.MatchString(rule) {
			return nil, fmt.Errorf("unexpected YARA output")
		}
		matches = append(matches, YaraMatch{Rule: rule, Offset: regionStart, Strings: []string{}})
	}
	return matches, nil
}

type boundedYaraOutput struct{ bytes.Buffer }

func (b *boundedYaraOutput) Write(p []byte) (int, error) {
	if b.Len()+len(p) > 1024*1024 {
		return 0, fmt.Errorf("YARA output exceeds 1 MiB")
	}
	return b.Buffer.Write(p)
}

func runYara(binary string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, binary, args...)
	var out, stderr boundedYaraOutput
	cmd.Stdout, cmd.Stderr = &out, &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("YARA engine failed: %w", err)
	}
	return out.Bytes(), nil
}
