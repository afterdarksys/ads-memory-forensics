package cmd

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/afterdarksystems/ads-memory-forensics/internal/memory"
	"github.com/spf13/cobra"
)

// authMiddleware enforces bearer token authentication on all routes except /health.
// Read token from ADS_MEMORY_API_TOKEN env var, or a randomly generated token
// printed to stderr at startup.
func authMiddleware(token string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			next.ServeHTTP(w, r)
			return
		}
		auth := r.Header.Get("Authorization")
		if auth != "Bearer "+token {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

var (
	servePort    int
	serveCert    string
	serveKey     string
	serveInsecure bool
)

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
		// Resolve API token: env var takes precedence, else generate random one.
		apiToken := os.Getenv("ADS_MEMORY_API_TOKEN")
		if apiToken == "" {
			buf := make([]byte, 16)
			if _, err := rand.Read(buf); err != nil {
				return fmt.Errorf("failed to generate API token: %w", err)
			}
			apiToken = hex.EncodeToString(buf)
			fmt.Fprintf(os.Stderr, "ADS_MEMORY_API_TOKEN=%s\n", apiToken)
		}

		// Check environment variables as fallback
		if serveCert == "" {
			if envCert := os.Getenv("TLS_CERT_PATH"); envCert != "" {
				serveCert = envCert
			}
		}
		if serveKey == "" {
			if envKey := os.Getenv("TLS_KEY_PATH"); envKey != "" {
				serveKey = envKey
			}
		}
		if os.Getenv("TLS_ENABLED") == "false" {
			serveInsecure = true
		}

		// Validate TLS config
		tlsEnabled := !serveInsecure
		if tlsEnabled && (serveCert == "" || serveKey == "") {
			fmt.Fprintln(os.Stderr, "Error: TLS enabled but --cert and --key not specified")
			fmt.Fprintln(os.Stderr, "Use --insecure to disable TLS (not recommended for production)")
			return fmt.Errorf("TLS configuration required")
		}

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
		protocol := "http"
		if tlsEnabled {
			protocol = "https"
		}
		fmt.Printf("ADS Memory Forensics API server starting on %s://%s\n", protocol, addr)
		fmt.Println("Endpoints: /health, /info, /regions, /scan, /dump")
		if tlsEnabled {
			fmt.Println("TLS: enabled")
		} else {
			fmt.Println("WARNING: TLS disabled - connections are not encrypted!")
		}
		if os.Geteuid() != 0 {
			fmt.Println("WARNING: Not running as root - scan/dump operations will fail")
		}

		handler := authMiddleware(apiToken, mux)
		if tlsEnabled {
			return http.ListenAndServeTLS(addr, serveCert, serveKey, handler)
		}
		return http.ListenAndServe(addr, handler)
	},
}

func init() {
	rootCmd.AddCommand(serveCmd)
	serveCmd.Flags().IntVarP(&servePort, "port", "p", 9002, "Port to listen on")
	serveCmd.Flags().StringVar(&serveCert, "cert", "", "TLS certificate file")
	serveCmd.Flags().StringVar(&serveKey, "key", "", "TLS key file")
	serveCmd.Flags().BoolVar(&serveInsecure, "insecure", false, "Disable TLS (not recommended for production)")
}
