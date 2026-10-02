package server

import (
	"archive/zip"
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"esign/internal/certstore"
)

const (
	testPort   = 47821
	testOrigin = "https://portal.example.com"
)

var testNow = time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)

type fakeSigner struct {
	crypto.Signer
	cert      *x509.Certificate
	signErr   error
	signCalls int
	closed    bool
}

func (f *fakeSigner) Sign(r io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	f.signCalls++
	if f.signErr != nil {
		return nil, f.signErr
	}
	return f.Signer.Sign(r, digest, opts)
}

func (f *fakeSigner) Certificate() *x509.Certificate { return f.cert }
func (f *fakeSigner) Close() error                   { f.closed = true; return nil }

type fakeStore struct {
	certs   []certstore.Certificate
	signer  *fakeSigner
	listErr error
	openErr error
}

func (s *fakeStore) List() ([]certstore.Certificate, error) { return s.certs, s.listErr }
func (s *fakeStore) Open(id string) (certstore.Signer, error) {
	if s.openErr != nil {
		return nil, s.openErr
	}
	return s.signer, nil
}

type fakeConfirmer struct {
	answer   bool
	calls    int
	title    string
	message  string
	duringFn func()
}

func (c *fakeConfirmer) Confirm(title, message string) bool {
	c.calls++
	c.title, c.message = title, message
	if c.duringFn != nil {
		c.duringFn()
	}
	return c.answer
}

type fixture struct {
	handler   http.Handler
	store     *fakeStore
	confirmer *fakeConfirmer
	cert      certstore.Certificate
}

func newFixture(t *testing.T, mutate func(*Config)) *fixture {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(42),
		Subject:      pkix.Name{CommonName: "AYSE DEMIR", SerialNumber: "10000000146"},
		NotBefore:    testNow.Add(-24 * time.Hour),
		NotAfter:     testNow.Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageContentCommitment,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	f := &fixture{
		cert:      certstore.Certificate{ID: "AABBCC", Cert: cert},
		confirmer: &fakeConfirmer{answer: true},
	}
	f.store = &fakeStore{
		certs:  []certstore.Certificate{f.cert},
		signer: &fakeSigner{Signer: key, cert: cert},
	}
	cfg := Config{
		Port:              testPort,
		Version:           "test",
		PlatformSupported: true,
		AllowedOrigins:    []string{testOrigin},
		Store:             f.store,
		Confirmer:         f.confirmer,
		Now:               func() time.Time { return testNow },
	}
	if mutate != nil {
		mutate(&cfg)
	}
	f.handler = New(cfg)
	return f
}

type request struct {
	method      string
	path        string
	host        string
	origin      string
	contentType string
	body        string
	header      map[string]string
}

func (f *fixture) do(r request) *httptest.ResponseRecorder {
	if r.method == "" {
		r.method = http.MethodGet
	}
	req := httptest.NewRequest(r.method, r.path, strings.NewReader(r.body))
	req.Host = r.host
	if req.Host == "" {
		req.Host = "127.0.0.1:47821"
	}
	if r.origin != "" {
		req.Header.Set("Origin", r.origin)
	}
	if r.contentType != "" {
		req.Header.Set("Content-Type", r.contentType)
	}
	for k, v := range r.header {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	f.handler.ServeHTTP(rec, req)
	return rec
}

func (f *fixture) post(origin string, body any) *httptest.ResponseRecorder {
	raw, _ := json.Marshal(body)
	return f.do(request{method: http.MethodPost, path: "/v1/sign", origin: origin, contentType: "application/json", body: string(raw)})
}

func assertError(t *testing.T, rec *httptest.ResponseRecorder, status int, code string) {
	t.Helper()
	if rec.Code != status {
		t.Fatalf("status = %d, want %d (body %s)", rec.Code, status, rec.Body)
	}
	var e errorBody
	if err := json.Unmarshal(rec.Body.Bytes(), &e); err != nil {
		t.Fatalf("error body: %v", err)
	}
	if e.Code != code || e.Message == "" {
		t.Fatalf("error = %+v, want code %q with a message", e, code)
	}
}

func makeUDF(t *testing.T, content string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, e := range []struct{ name, body string }{
		{"content.xml", content},
		{"documentproperties.xml", "<properties/>"},
	} {
		w, err := zw.Create(e.name)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = w.Write([]byte(e.body))
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func doc(id, name, format string, data []byte) map[string]string {
	return map[string]string{"id": id, "name": name, "format": format, "data": base64.StdEncoding.EncodeToString(data)}
}
