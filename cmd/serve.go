package cmd

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/afterdarksystems/ads-memory-forensics/internal/memory"
	"github.com/spf13/cobra"
)

var servePort int

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Run as HTTP JSON API server",
	Long: `Run ads-memory-forensics as an HTTP server exposing JSON API endpoints.

Endpoints:
  GET  /health              - Health check
  GET  /info                - Tool version and capabilities
  GET  /regions?pid=N       - List memory regions for process
  POST /scan                - Scan process memory (JSON body with options)
  POST /dump                - Dump process memory (JSON body with options)

Requires root privileges for scan and dump operations.

This mode is used by the ADS Security Console GUI.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		mux := http.NewServeMux()

		// Health check
		mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"status": "healthy",
				"time":   time.Now().UTC().Format(time.RFC3339),
				"root":   os.Geteuid() == 0,
			})
		})

		// Info
		mux.HandleFunc("/info", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"name":    "ads-memory-forensics",
				"version": Version,
				"endpoints": []string{
					"/health",
					"/info",
					"/regions?pid=N",
					"/scan (POST)",
					"/dump (POST)",
				},
				"requires_root": true,
			})
		})

		// List regions
		mux.HandleFunc("/regions", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")

			pidStr := r.URL.Query().Get("pid")
			if pidStr == "" {
				w.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(w).Encode(map[string]string{"error": "pid parameter required"})
				return
			}

			pid, err := strconv.ParseInt(pidStr, 10, 32)
			if err != nil {
				w.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(w).Encode(map[string]string{"error": "invalid pid"})
				return
			}

			regions, err := memory.ListRegions(int32(pid))
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
				return
			}

			json.NewEncoder(w).Encode(map[string]interface{}{
				"version":   Version,
				"pid":       pid,
				"count":     len(regions),
				"timestamp": time.Now().UTC().Format(time.RFC3339),
				"regions":   regions,
			})
		})

		// Scan memory
		mux.HandleFunc("/scan", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")

			if r.Method != http.MethodPost {
				w.WriteHeader(http.StatusMethodNotAllowed)
				json.NewEncoder(w).Encode(map[string]string{"error": "POST required"})
				return
			}

			var opts memory.ScanOptions
			if err := json.NewDecoder(r.Body).Decode(&opts); err != nil {
				w.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(w).Encode(map[string]string{"error": "invalid JSON: " + err.Error()})
				return
			}

			if opts.PID <= 0 {
				w.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(w).Encode(map[string]string{"error": "pid required"})
				return
			}

			result, err := memory.ScanProcess(opts)
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
				return
			}

			json.NewEncoder(w).Encode(result)
		})

		addr := fmt.Sprintf("127.0.0.1:%d", servePort)
		fmt.Printf("ADS Memory Forensics API server starting on http://%s\n", addr)
		fmt.Println("Endpoints: /health, /info, /regions, /scan, /dump")
		if os.Geteuid() != 0 {
			fmt.Println("WARNING: Not running as root - scan/dump operations will fail")
		}

		return http.ListenAndServe(addr, mux)
	},
}

func init() {
	rootCmd.AddCommand(serveCmd)
	serveCmd.Flags().IntVarP(&servePort, "port", "p", 9002, "Port to listen on")
}
