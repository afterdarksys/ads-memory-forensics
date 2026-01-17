package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var (
	outputJSON bool
	Version    = "0.1.0"
)

var rootCmd = &cobra.Command{
	Use:   "ads-memory-forensics",
	Short: "macOS Memory Forensics Tool",
	Long: `ADS Memory Forensics - Memory analysis and artifact extraction for macOS.

Dump process memory, extract credentials, detect injected code, and hunt
for memory-resident threats.

Part of the ADS macOS Security Suite.`,
	Version: Version,
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentFlags().BoolVar(&outputJSON, "output-json", false, "Output results as JSON")
}
