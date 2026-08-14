package oob

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// mockServer returns a minimal interactsh-compatible server for testing.
// It accepts one registration and one poll request, then returns the
// pre-baked callback entry.
func mockServer(t *testing.T, callback map[string]string) (*httptest.Server, *rsa.PublicKey) {
	t.Helper()
	var capturedPub *rsa.PublicKey

	mux := http.NewServeMux()
	mux.HandleFunc("/register", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			PublicKey string `json:"public-key"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "bad body", http.StatusBadRequest)
			return
		}
		pubDER, err := base64.StdEncoding.DecodeString(body.PublicKey)
		if err != nil {
			http.Error(w, "bad key", http.StatusBadRequest)
			return
		}
		pub, err := x509.ParsePKIXPublicKey(pubDER)
		if err != nil {
			http.Error(w, "bad key format", http.StatusBadRequest)
			return
		}
		capturedPub, _ = pub.(*rsa.PublicKey)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"message": "registration successful"})
	})

	mux.HandleFunc("/poll", func(w http.ResponseWriter, r *http.Request) {
		if capturedPub == nil {
			http.NotFound(w, r)
			return
		}
		// Build a real AES-GCM encrypted response the client can decrypt.
		entryJSON, _ := json.Marshal(callback)

		aesKey := make([]byte, 32)
		rand.Read(aesKey)

		block, _ := aes.NewCipher(aesKey)
		gcm, _ := cipher.NewGCM(block)
		nonce := make([]byte, gcm.NonceSize())
		rand.Read(nonce)
		ct := gcm.Seal(nonce, nonce, entryJSON, nil)

		encKey, _ := rsa.EncryptOAEP(sha256.New(), rand.Reader, capturedPub, aesKey, nil)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"data":    []string{base64.StdEncoding.EncodeToString(ct)},
			"aes_key": base64.StdEncoding.EncodeToString(encKey),
		})
	})

	return httptest.NewServer(mux), capturedPub
}

func TestRegister_Success(t *testing.T) {
	srv, _ := mockServer(t, nil)
	defer srv.Close()

	session, err := Register(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if session.Host == "" {
		t.Error("session.Host should not be empty after registration")
	}
	if !strings.Contains(session.Host, session.correlationID) {
		t.Errorf("session.Host %q should contain correlationID %q", session.Host, session.correlationID)
	}
}

func TestRegister_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	_, err := Register(context.Background(), srv.URL)
	if err == nil {
		t.Error("Register should fail when server returns non-200")
	}
}

func TestPoll_ReceivesCallback(t *testing.T) {
	cb := map[string]string{
		"protocol":       "http",
		"unique-id":      "abc123",
		"remote-address": "1.2.3.4:50000",
		"raw-request":    "GET / HTTP/1.1",
		"timestamp":      time.Now().UTC().Format(time.RFC3339),
	}
	srv, _ := mockServer(t, cb)
	defer srv.Close()

	session, err := Register(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("Register: %v", err)
	}

	callbacks, err := session.Poll(context.Background())
	if err != nil {
		t.Fatalf("Poll: %v", err)
	}
	if len(callbacks) != 1 {
		t.Fatalf("expected 1 callback, got %d", len(callbacks))
	}
	if callbacks[0].Protocol != "http" {
		t.Errorf("expected protocol=http, got %q", callbacks[0].Protocol)
	}
	if callbacks[0].RemoteAddr != "1.2.3.4:50000" {
		t.Errorf("expected remote-address=1.2.3.4:50000, got %q", callbacks[0].RemoteAddr)
	}
}

func TestPoll_NoCallbacks(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/register") {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{"message": "registration successful"})
			return
		}
		// poll returns 404 when no callbacks yet
		http.NotFound(w, r)
	}))
	defer srv.Close()

	session, err := Register(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("Register: %v", err)
	}

	callbacks, err := session.Poll(context.Background())
	if err != nil {
		t.Fatalf("Poll with no callbacks should not error: %v", err)
	}
	if len(callbacks) != 0 {
		t.Errorf("expected 0 callbacks on 404 poll, got %d", len(callbacks))
	}
}

func TestToFinding_Shape(t *testing.T) {
	cb := Callback{
		Protocol:   "http",
		RemoteAddr: "1.2.3.4:50000",
		Timestamp:  time.Now(),
	}
	f := ToFinding(cb, "test", "https://example.com")
	if f.ID != "MANTIS-OOB" {
		t.Errorf("unexpected finding ID: %q", f.ID)
	}
	if f.CWE != "CWE-918" {
		t.Errorf("expected CWE-918, got %q", f.CWE)
	}
	if f.Confidence != 0.9 {
		t.Errorf("expected confidence 0.9, got %v", f.Confidence)
	}
}
