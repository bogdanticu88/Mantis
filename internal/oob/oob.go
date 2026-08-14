// Package oob implements out-of-band (OOB) detection for Mantis using the
// interactsh protocol. Templates that include {{oob_host}} in their payloads
// can detect blind vulnerabilities (SSRF, blind injection, XXE) by checking
// whether the target application made an outbound connection to the OOB server.
//
// Compatible with interact.sh (public, free) and self-hosted interactsh servers.
package oob

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/bogdanticu88/Mantis/internal/findings"
)

// Callback is one OOB interaction received by the server (HTTP, DNS, SMTP).
type Callback struct {
	Protocol   string
	UniqueID   string
	RemoteAddr string
	RawData    string
	Timestamp  time.Time
}

// Session is a registered OOB session. Host is the callback hostname to
// embed in payloads. Poll returns any callbacks received since registration.
type Session struct {
	Host          string
	server        string
	correlationID string
	secretKey     string
	privKey       *rsa.PrivateKey
}

// Register creates a new session with an interactsh-compatible server.
// If serverURL is empty the public interact.sh instance is used. The returned
// session's Host field is safe to embed directly in payloads as a callback
// address (e.g. "{{oob_host}}" in a template path or body).
func Register(ctx context.Context, serverURL string) (*Session, error) {
	if serverURL == "" {
		serverURL = "https://interact.sh"
	}

	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("oob: generating RSA key: %w", err)
	}

	corrID := randomID(13)
	secret := randomID(32)

	pubDER, err := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("oob: encoding public key: %w", err)
	}

	body, _ := json.Marshal(map[string]string{
		"public-key":     base64.StdEncoding.EncodeToString(pubDER),
		"secret-key":     secret,
		"correlation-id": corrID,
	})

	endpoint := strings.TrimRight(serverURL, "/") + "/register"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("oob: building register request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("oob: register request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("oob: register returned %d: %s", resp.StatusCode, string(body))
	}

	// The OOB callback hostname is <corrId>.<server-domain>.
	// Any request to that host (or its subdomains) will be logged.
	host := corrID + "." + serverHost(serverURL)

	return &Session{
		Host:          host,
		server:        serverURL,
		correlationID: corrID,
		secretKey:     secret,
		privKey:       privKey,
	}, nil
}

// Poll fetches callbacks that have arrived since registration. Returns nil
// slice (not an error) when no callbacks have been received yet.
func (s *Session) Poll(ctx context.Context) ([]Callback, error) {
	params := url.Values{"id": {s.correlationID}, "secret": {s.secretKey}}
	endpoint := strings.TrimRight(s.server, "/") + "/poll?" + params.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("oob: building poll request: %w", err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("oob: poll request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}

	var result struct {
		Data   []string `json:"data"`
		AESKey string   `json:"aes_key"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("oob: decoding poll response: %w", err)
	}
	if len(result.Data) == 0 || result.AESKey == "" {
		return nil, nil
	}

	encKey, err := base64.StdEncoding.DecodeString(result.AESKey)
	if err != nil {
		return nil, fmt.Errorf("oob: decoding AES key: %w", err)
	}
	aesKey, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, s.privKey, encKey, nil)
	if err != nil {
		return nil, fmt.Errorf("oob: decrypting AES key: %w", err)
	}

	var callbacks []Callback
	for _, enc := range result.Data {
		raw, err := base64.StdEncoding.DecodeString(enc)
		if err != nil {
			continue
		}
		plain, err := aesGCMDecrypt(aesKey, raw)
		if err != nil {
			continue
		}
		var entry struct {
			Protocol   string `json:"protocol"`
			UniqueID   string `json:"unique-id"`
			RemoteAddr string `json:"remote-address"`
			RawRequest string `json:"raw-request"`
			Timestamp  string `json:"timestamp"`
		}
		if err := json.Unmarshal(plain, &entry); err != nil {
			continue
		}
		ts, _ := time.Parse(time.RFC3339, entry.Timestamp)
		if ts.IsZero() {
			ts = time.Now()
		}
		callbacks = append(callbacks, Callback{
			Protocol:   entry.Protocol,
			UniqueID:   entry.UniqueID,
			RemoteAddr: entry.RemoteAddr,
			RawData:    entry.RawRequest,
			Timestamp:  ts,
		})
	}
	return callbacks, nil
}

// ToFinding converts a received OOB callback into a finding for the report.
func ToFinding(cb Callback, environment, target string) findings.Finding {
	return findings.Finding{
		ID:          "MANTIS-OOB",
		Name:        fmt.Sprintf("Out-of-Band %s Callback Received", strings.ToUpper(cb.Protocol)),
		Severity:    findings.SeverityHigh,
		Confidence:  0.9,
		Environment: environment,
		Target:      target,
		Endpoint:    target,
		Method:      "",
		Description: fmt.Sprintf("The target application made an out-of-band %s connection to the OOB callback server (source: %s). This confirms the application issued an outbound request triggered by injected input, commonly indicating SSRF, blind command injection, blind XXE, or similar blind vulnerabilities.", strings.ToUpper(cb.Protocol), cb.RemoteAddr),
		CWE:         "CWE-918",
		OWASP:       "A10:2021-Server-Side Request Forgery",
		Tags:        []string{"oob", cb.Protocol},
		Evidence: findings.Evidence{
			Description: fmt.Sprintf("OOB %s callback from %s at %s", strings.ToUpper(cb.Protocol), cb.RemoteAddr, cb.Timestamp.Format(time.RFC3339)),
			MatchedOn:   []string{fmt.Sprintf("%s callback from %s", cb.Protocol, cb.RemoteAddr)},
		},
		Timestamp: cb.Timestamp,
	}
}

func aesGCMDecrypt(key, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}
	return gcm.Open(nil, ciphertext[:nonceSize], ciphertext[nonceSize:], nil)
}

func serverHost(serverURL string) string {
	u, err := url.Parse(serverURL)
	if err != nil {
		return serverURL
	}
	return u.Hostname()
}

func randomID(n int) string {
	const alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, n)
	rand.Read(b) //nolint:errcheck // rand.Read from crypto/rand never fails
	for i, v := range b {
		b[i] = alphabet[int(v)%len(alphabet)]
	}
	return string(b)
}
