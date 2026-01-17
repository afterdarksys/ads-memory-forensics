package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/afterdarksystems/ads-memory-forensics/internal/memory"
	"github.com/spf13/cobra"
)

var regionsPID int32

var regionsCmd = &cobra.Command{
	Use:   "regions",
	Short: "List memory regions of a process",
	Long: `List all memory regions of a process with protection flags.

Shows:
  - Address range
  - Size
  - Protection (read/write/execute)
  - Region type (heap, stack, mapped file, etc.)

Examples:
  ads-memory-forensics regions --pid 1234
  ads-memory-forensics regions --pid 1234 --output-json`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if regionsPID <= 0 {
			return fmt.Errorf("--pid is required")
		}

		regions, err := memory.ListRegions(regionsPID)
		if err != nil {
			return fmt.Errorf("failed to list regions: %w", err)
		}

		if outputJSON {
			output := map[string]interface{}{
				"version": Version,
				"pid":     regionsPID,
				"count":   len(regions),
				"regions": regions,
			}
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(output)
		}

		fmt.Printf("Memory regions for PID %d (%d total)\n\n", regionsPID, len(regions))

		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "START\tEND\tSIZE\tPROT\tTYPE\tPATH")
		fmt.Fprintln(w, "-----\t---\t----\t----\t----\t----")

		for _, r := range regions {
			prot := ""
			if r.Readable {
				prot += "r"
			} else {
				prot += "-"
			}
			if r.Writable {
				prot += "w"
			} else {
				prot += "-"
			}
			if r.Executable {
				prot += "x"
			} else {
				prot += "-"
			}

			path := r.Path
			if len(path) > 40 {
				path = "..." + path[len(path)-37:]
			}

			fmt.Fprintf(w, "0x%x\t0x%x\t%s\t%s\t%s\t%s\n",
				r.Start, r.End, formatBytes(r.Size), prot, r.Type, path)
		}

		return w.Flush()
	},
}

func init() {
	rootCmd.AddCommand(regionsCmd)
	regionsCmd.Flags().Int32VarP(&regionsPID, "pid", "p", 0, "Process ID (required)")
}
