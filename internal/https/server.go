// Package https provides HTTPS server functionality for receiving exfiltrated files.
//
// The server uses TLS with a self-signed certificate. For this simulation,
// certificate validation is not critical—we just need encrypted transport
// to make the traffic look realistic.
package https

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

// Server handles HTTPS connections for file uploads.
type Server struct {
	port      int
	certDir   string
	outputDir string
}

// NewServer creates a new HTTPS server.
//
// Parameters:
//   - port: Port to listen on (e.g., 8443)
//   - certDir: Directory containing cert.pem and key.pem (auto-generated if missing)
//   - outputDir: Directory to save uploaded files
func NewServer(port int, certDir, outputDir string) *Server {
	return &Server{
		port:      port,
		certDir:   certDir,
		outputDir: outputDir,
	}
}

// Start begins listening for HTTPS connections.
// This function blocks, so run it in a goroutine.
func (s *Server) Start() error {
	// Ensure output directory exists
	if err := os.MkdirAll(s.outputDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	// Ensure certificates exist (generate if needed)
	certFile := filepath.Join(s.certDir, "cert.pem")
	keyFile := filepath.Join(s.certDir, "key.pem")

	if err := s.ensureCertificates(certFile, keyFile); err != nil {
		return fmt.Errorf("failed to ensure certificates: %w", err)
	}

	// Set up HTTP handlers
	mux := http.NewServeMux()
	mux.HandleFunc("/upload", s.handleUpload)
	mux.HandleFunc("/health", s.handleHealth)

	addr := fmt.Sprintf(":%d", s.port)
	log.Printf("[HTTPS] Starting server on %s", addr)
	log.Printf("[HTTPS] Upload endpoint: POST /upload")
	log.Printf("[HTTPS] Files will be saved to: %s", s.outputDir)

	return http.ListenAndServeTLS(addr, certFile, keyFile, mux)
}

// handleUpload receives a file upload from the agent.
//
// Expected request:
//   - Method: POST
//   - Header X-Filename: Original filename
//   - Body: Raw file bytes
//
// The file is saved to outputDir with a timestamp prefix.
func (s *Server) handleUpload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed. Use POST.", http.StatusMethodNotAllowed)
		return
	}

	// Get filename from header (or use default)
	filename := r.Header.Get("X-Filename")
	if filename == "" {
		filename = "uploaded_file"
	}

	// Add timestamp prefix to avoid overwrites
	timestamp := time.Now().Format("20060102-150405")
	outputFilename := fmt.Sprintf("%s_%s", timestamp, filepath.Base(filename))
	outputPath := filepath.Join(s.outputDir, outputFilename)

	log.Printf("[HTTPS] Receiving file: %s", outputFilename)

	// Create output file
	outFile, err := os.Create(outputPath)
	if err != nil {
		log.Printf("[HTTPS] Failed to create file: %v", err)
		http.Error(w, "Failed to create file", http.StatusInternalServerError)
		return
	}
	defer outFile.Close()

	// Stream body to file (handles large files efficiently)
	startTime := time.Now()
	bytesWritten, err := io.Copy(outFile, r.Body)
	if err != nil {
		log.Printf("[HTTPS] Failed to write file: %v", err)
		http.Error(w, "Failed to write file", http.StatusInternalServerError)
		return
	}

	elapsed := time.Since(startTime)
	mbWritten := float64(bytesWritten) / 1024 / 1024
	mbPerSec := mbWritten / elapsed.Seconds()

	log.Printf("[HTTPS] File received: %s (%.2f MB in %v, %.2f MB/s)",
		outputFilename, mbWritten, elapsed, mbPerSec)

	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "Received %d bytes\n", bytesWritten)
}

// handleHealth is a simple health check endpoint.
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	fmt.Fprintln(w, "OK")
}

// ensureCertificates checks if cert/key exist, generates them if not.
func (s *Server) ensureCertificates(certFile, keyFile string) error {
	// Check if both files exist
	_, certErr := os.Stat(certFile)
	_, keyErr := os.Stat(keyFile)

	if certErr == nil && keyErr == nil {
		log.Printf("[HTTPS] Using existing certificates from %s", s.certDir)
		return nil
	}

	log.Printf("[HTTPS] Generating self-signed certificate...")

	// Ensure cert directory exists
	if err := os.MkdirAll(s.certDir, 0755); err != nil {
		return fmt.Errorf("failed to create cert directory: %w", err)
	}

	// Generate private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("failed to generate private key: %w", err)
	}

	// Create certificate template
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"DNS Tunnel Simulator"},
			CommonName:   "localhost",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour), // 1 year
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	// Self-sign the certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return fmt.Errorf("failed to create certificate: %w", err)
	}

	// Write certificate to file
	certOut, err := os.Create(certFile)
	if err != nil {
		return fmt.Errorf("failed to create cert file: %w", err)
	}
	defer certOut.Close()

	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: certDER}); err != nil {
		return fmt.Errorf("failed to write cert file: %w", err)
	}

	// Write private key to file
	keyOut, err := os.Create(keyFile)
	if err != nil {
		return fmt.Errorf("failed to create key file: %w", err)
	}
	defer keyOut.Close()

	privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	if err := pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: privateKeyBytes}); err != nil {
		return fmt.Errorf("failed to write key file: %w", err)
	}

	log.Printf("[HTTPS] Generated new certificates in %s", s.certDir)
	return nil
}
