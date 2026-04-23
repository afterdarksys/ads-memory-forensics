package main

import (
	"fmt"
	"net"
	"os"
	"time"
)

func main() {
	// 1. Strings in memory
	email := "target_user@sensitive-corp.com"
	domain := "malicious-c2-server.xyz"
	ip := "192.168.99.100"
	apiKey := "ghp_1234567890abcdef1234567890abcdef1234" // Fake GitHub token
	jsonData := `{"user": "admin", "role": "superuser", "access": true}`

	// Crypto Wallets
	btc := "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
	eth := "0x742d35Cc6634C0532925a3b844Bc454e4438f44e"
	sol := "5U3bKWcuyxY8D7Lp8wE3Yg9y9k5y9k5y9k5y9k5y9k5y"

	// Keep them alive and used
	go func() {
		for {
			_ = fmt.Sprintf("%s %s %s %s %s %s %s %s", email, domain, ip, apiKey, jsonData, btc, eth, sol)
			time.Sleep(1 * time.Second)
		}
	}()

	// 2. Open Network Connection
	listener, err := net.Listen("tcp", "127.0.0.1:0") // Random port
	if err != nil {
		panic(err)
	}
	defer listener.Close()

	addr := listener.Addr().(*net.TCPAddr)
	fmt.Printf("Listening on port %d... PID: %d\n", addr.Port, os.Getpid())

	// Block forever
	select {}
}
