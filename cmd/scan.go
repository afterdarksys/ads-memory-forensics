package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/afterdarksystems/ads-memory-forensics/internal/memory"
	"github.com/spf13/cobra"
)

var (
	scanPID       int32
	scanSecrets   bool
	scanInjection bool
	scanStrings   bool
	scanYara      string
)

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Scan process memory for artifacts",
	Long: `Scan process memory for security-relevant artifacts.

Detects:
  - Credentials and secrets (API keys, passwords, tokens)
  - Code injection (shellcode, ROP gadgets)
  - Suspicious strings (URLs, IPs, commands)
  - YARA rule matches (with --yara flag)

Requires root privileges on macOS.

Examples:
  # Scan for secrets
  sudo ads-memory-forensics scan --pid 1234 --secrets

  # Scan for code injection
  sudo ads-memory-forensics scan --pid 1234 --injection

  # Full scan with YARA rules
  sudo ads-memory-forensics scan --pid 1234 --yara rules.yar`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if scanPID <= 0 {
			return fmt.Errorf("--pid is required")
		}

		if os.Geteuid() != 0 {
			return fmt.Errorf("root privileges required for memory scan")
		}

		opts := memory.ScanOptions{
			PID:            scanPID,
			ScanSecrets:    scanSecrets,
			ScanInjection:  scanInjection,
			ScanStrings:    scanStrings,
			YaraRulesPath:  scanYara,
		}

		// If no specific scan type, enable all
		if !scanSecrets && !scanInjection && !scanStrings && scanYara == "" {
			opts.ScanSecrets = true
			opts.ScanInjection = true
			opts.ScanStrings = true
		}

		result, err := memory.ScanProcess(opts)
		if err != nil {
			return fmt.Errorf("memory scan failed: %w", err)
		}

		if outputJSON {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(result)
		}

		return outputScanResults(result)
	},
}

func outputScanResults(result *memory.ScanResult) error {
	fmt.Printf("Memory Scan Results for PID %d (%s)\n", result.PID, result.ProcessName)
	fmt.Printf("Scanned: %s across %d regions\n\n", formatBytes(result.BytesScanned), result.RegionsScanned)

	if len(result.Secrets) > 0 {
		fmt.Println("=== Secrets Found ===")
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "TYPE\tVALUE\tOFFSET\tCONFIDENCE")
		for _, s := range result.Secrets {
			value := s.Value
			if len(value) > 40 {
				value = value[:37] + "..."
			}
			fmt.Fprintf(w, "%s\t%s\t0x%x\t%d%%\n", s.Type, value, s.Offset, s.Confidence)
		}
		w.Flush()
		fmt.Println()
	}

	if len(result.Injections) > 0 {
		fmt.Println("=== Injection Indicators ===")
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "TYPE\tOFFSET\tSIZE\tDESCRIPTION")
		for _, i := range result.Injections {
			fmt.Fprintf(w, "%s\t0x%x\t%d\t%s\n", i.Type, i.Offset, i.Size, i.Description)
		}
		w.Flush()
		fmt.Println()
	}

	if len(result.Strings) > 0 {
		fmt.Println("=== Suspicious Strings ===")
		for _, s := range result.Strings {
			if len(s) > 100 {
				s = s[:97] + "..."
			}
			fmt.Printf("  %s\n", s)
		}
		fmt.Println()
	}

	if len(result.YaraMatches) > 0 {
		fmt.Println("=== YARA Matches ===")
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "RULE\tOFFSET\tSTRINGS")
		for _, m := range result.YaraMatches {
			fmt.Fprintf(w, "%s\t0x%x\t%v\n", m.Rule, m.Offset, m.Strings)
		}
		w.Flush()
		fmt.Println()
	}

	// Summary
	fmt.Println("=== Summary ===")
	fmt.Printf("  Secrets: %d\n", len(result.Secrets))
	fmt.Printf("  Injection indicators: %d\n", len(result.Injections))
	fmt.Printf("  Suspicious strings: %d\n", len(result.Strings))
	fmt.Printf("  YARA matches: %d\n", len(result.YaraMatches))

	if result.ThreatScore > 0 {
		fmt.Printf("\n  Threat Score: %d/100\n", result.ThreatScore)
	}

	return nil
}

func init() {
	rootCmd.AddCommand(scanCmd)
	scanCmd.Flags().Int32VarP(&scanPID, "pid", "p", 0, "Process ID to scan (required)")
	scanCmd.Flags().BoolVarP(&scanSecrets, "secrets", "s", false, "Scan for credentials and secrets")
	scanCmd.Flags().BoolVarP(&scanInjection, "injection", "i", false, "Scan for code injection")
	scanCmd.Flags().BoolVarP(&scanStrings, "strings", "t", false, "Extract suspicious strings")
	scanCmd.Flags().StringVarP(&scanYara, "yara", "y", "", "Path to YARA rules file")
}
