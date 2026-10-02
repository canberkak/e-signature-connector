package server

import (
	"crypto/x509"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"esign/internal/certstore"
)

func TestHostAndOriginGuard(t *testing.T) {
	f := newFixture(t, nil)

	assertError(t, f.do(request{path: "/v1/status", host: "evil.example.com:47821"}), 403, "request.invalid_host")
	assertError(t, f.do(request{path: "/v1/status", host: "127.0.0.1"}), 403, "request.invalid_host")
	assertError(t, f.do(request{path: "/v1/status", origin: "https://evil.example.com"}), 403, "request.origin_not_allowed")
	assertError(t, f.do(request{path: "/v1/status", origin: "null"}), 403, "request.origin_not_allowed")
	assertError(t, f.do(request{method: http.MethodPost, path: "/v1/sign", contentType: "application/json", body: "{}"}), 403, "request.origin_not_allowed")
	assertError(t, f.do(request{method: http.MethodOptions, path: "/v1/sign"}), 403, "request.origin_not_allowed")

	for _, host := range []string{"127.0.0.1:47821", "localhost:47821", "LOCALHOST:47821"} {
		if rec := f.do(request{path: "/v1/status", host: host}); rec.Code != http.StatusOK {
			t.Errorf("host %q: status %d", host, rec.Code)
		}
	}
}

func TestCORS(t *testing.T) {
	f := newFixture(t, nil)

	rec := f.do(request{
		method: http.MethodOptions, path: "/v1/sign", origin: testOrigin,
		header: map[string]string{"Access-Control-Request-Private-Network": "true"},
	})
	if rec.Code != http.StatusNoContent {
		t.Fatalf("preflight status = %d", rec.Code)
	}
	h := rec.Header()
	if h.Get("Access-Control-Allow-Origin") != testOrigin || h.Get("Access-Control-Allow-Private-Network") != "true" {
		t.Errorf("preflight headers = %v", h)
	}

	rec = f.do(request{path: "/v1/status", origin: testOrigin})
	if rec.Header().Get("Access-Control-Allow-Origin") != testOrigin {
		t.Errorf("missing allow-origin on simple request: %v", rec.Header())
	}
	if rec.Header().Get("Access-Control-Allow-Private-Network") != "" {
		t.Error("private-network header must only answer a request that asked for it")
	}
}

func TestDemoOriginIsAllowedOnlyWithDemo(t *testing.T) {
	self := "http://127.0.0.1:47821"

	f := newFixture(t, nil)
	assertError(t, f.do(request{path: "/v1/status", origin: self}), 403, "request.origin_not_allowed")

	f = newFixture(t, func(c *Config) {
		c.Demo = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("demo")) })
	})
	if rec := f.do(request{path: "/v1/status", origin: self}); rec.Code != http.StatusOK {
		t.Errorf("demo origin status = %d", rec.Code)
	}
	if rec := f.do(request{path: "/"}); rec.Body.String() != "demo" {
		t.Errorf("demo page = %q", rec.Body)
	}
	assertError(t, f.do(request{path: "/v1/unknown"}), 404, "request.not_found")
}

func TestRoutes(t *testing.T) {
	f := newFixture(t, nil)

	assertError(t, f.do(request{path: "/nope"}), 404, "request.not_found")
	assertError(t, f.do(request{method: http.MethodPost, path: "/v1/status", origin: testOrigin}), 405, "request.method_not_allowed")
	assertError(t, f.do(request{path: "/v1/sign", origin: testOrigin}), 405, "request.method_not_allowed")

	rec := f.do(request{path: "/v1/status"})
	var status struct {
		Version           string `json:"version"`
		PlatformSupported bool   `json:"platformSupported"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &status); err != nil || status.Version != "test" || !status.PlatformSupported {
		t.Errorf("status = %s (%v)", rec.Body, err)
	}
}

func TestCertificates(t *testing.T) {
	f := newFixture(t, nil)

	rec := f.do(request{path: "/v1/certificates", origin: testOrigin})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body)
	}
	var infos []certificateInfo
	if err := json.Unmarshal(rec.Body.Bytes(), &infos); err != nil || len(infos) != 1 {
		t.Fatalf("body = %s (%v)", rec.Body, err)
	}
	got := infos[0]
	want := certificateInfo{
		ID:             "AABBCC",
		Subject:        "AYSE DEMIR",
		IdentityNumber: "10000000146",
		Issuer:         "AYSE DEMIR",
		NotBefore:      "2026-04-30T12:00:00Z",
		NotAfter:       "2026-05-02T12:00:00Z",
		KeyAlgorithm:   "ECDSA P-384",
		Qualified:      false,
		Valid:          true,
	}
	if got != want {
		t.Errorf("info = %+v, want %+v", got, want)
	}
}

func TestCertificateValidity(t *testing.T) {
	f := newFixture(t, nil)
	cert := f.cert.Cert

	if !describe(f.cert, testNow).Valid {
		t.Fatal("fixture certificate should be valid")
	}
	if describe(f.cert, cert.NotAfter.Add(time.Second)).Valid {
		t.Error("expired certificate reported valid")
	}
	if describe(f.cert, cert.NotBefore.Add(-time.Second)).Valid {
		t.Error("not-yet-valid certificate reported valid")
	}

	encipherOnly := *cert
	encipherOnly.KeyUsage = x509.KeyUsageKeyEncipherment
	if describe(certstore.Certificate{ID: "X", Cert: &encipherOnly}, testNow).Valid {
		t.Error("certificate without signing key usage reported valid")
	}
	noUsage := *cert
	noUsage.KeyUsage = 0
	if !describe(certstore.Certificate{ID: "X", Cert: &noUsage}, testNow).Valid {
		t.Error("certificate without keyUsage extension should be valid")
	}
}

func TestCertificatesEmptyIsArray(t *testing.T) {
	f := newFixture(t, func(c *Config) { c.Store = &fakeStore{} })
	rec := f.do(request{path: "/v1/certificates", origin: testOrigin})
	if strings.TrimSpace(rec.Body.String()) != "[]" {
		t.Errorf("body = %q, want []", rec.Body)
	}
}

func TestPlatformUnsupported(t *testing.T) {
	f := newFixture(t, func(c *Config) { c.PlatformSupported = false })
	assertError(t, f.do(request{path: "/v1/certificates", origin: testOrigin}), 501, "platform.unsupported")
	assertError(t, f.post(testOrigin, map[string]any{"certificateId": "AABBCC", "documents": []any{doc("1", "a.bin", "cms", []byte("x"))}}), 501, "platform.unsupported")

	f = newFixture(t, nil)
	f.store.listErr = errors.ErrUnsupported
	assertError(t, f.do(request{path: "/v1/certificates", origin: testOrigin}), 501, "platform.unsupported")
}

func TestListFailureIsInternal(t *testing.T) {
	f := newFixture(t, nil)
	f.store.listErr = errors.New("boom")
	rec := f.do(request{path: "/v1/certificates", origin: testOrigin})
	assertError(t, rec, 500, "internal")
	if strings.Contains(rec.Body.String(), "boom") {
		t.Error("internal error detail leaked to the page")
	}
}
