package cmd

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/afterdarksystems/ads-memory-forensics/internal/memory"
	"github.com/spf13/cobra"
)

var (
	dumpPID    int32
	dumpOutput string
	dumpAll    bool
)

var dumpCmd = &cobra.Command{
	Use:   "dump",
	Short: "Dump process memory",
	Long: `Dump memory regions from a process for forensic analysis.

Requires root privileges on macOS.

Examples:
  # Dump specific process
  sudo ads-memory-forensics dump --pid 1234 --output /tmp/dump.bin

  # Dump to stdout (for piping)
  sudo ads-memory-forensics dump --pid 1234 > dump.bin`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if dumpPID <= 0 {
			return fmt.Errorf("--pid is required")
		}

		if os.Geteuid() != 0 {
			return fmt.Errorf("root privileges required for memory dump")
		}

		result, err := memory.DumpProcess(dumpPID, dumpOutput, dumpAll)
		if err != nil {
			return fmt.Errorf("memory dump failed: %w", err)
		}

		if outputJSON {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(result)
		}

		fmt.Printf("Memory dump complete for PID %d\n", dumpPID)
		fmt.Printf("  Regions dumped: %d\n", result.RegionCount)
		fmt.Printf("  Total size: %s\n", formatBytes(result.TotalSize))
		if dumpOutput != "" {
			fmt.Printf("  Output file: %s\n", dumpOutput)
		}

		return nil
	},
}

func formatBytes(b uint64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := uint64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}

func init() {
	rootCmd.AddCommand(dumpCmd)
	dumpCmd.Flags().Int32VarP(&dumpPID, "pid", "p", 0, "Process ID to dump (required)")
	dumpCmd.Flags().StringVarP(&dumpOutput, "output", "o", "", "Output file path")
	dumpCmd.Flags().BoolVarP(&dumpAll, "all", "a", false, "Dump all memory regions (not just readable)")
}
