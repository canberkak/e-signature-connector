package server

import (
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"esign/internal/certstore"
)

const (
	DefaultPort  = 47821
	maxBodyBytes = 50 << 20
)

type Store interface {
	List() ([]certstore.Certificate, error)
	Open(id string) (certstore.Signer, error)
}

// Confirmer shows the native confirmation window; the page can never skip it.
type Confirmer interface {
	Confirm(title, message string) bool
}

type Config struct {
	Port              int
	Version           string
	PlatformSupported bool
	AllowedOrigins    []string
	// Demo serves non-API paths from the connector itself; its origin counts as allowed.
	Demo      http.Handler
	Store     Store
	Confirmer Confirmer
	Now       func() time.Time
}

type server struct {
	cfg     Config
	hosts   map[string]bool
	origins map[string]bool
	signing sync.Mutex
}

func New(cfg Config) http.Handler {
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	port := strconv.Itoa(cfg.Port)
	s := &server{
		cfg:     cfg,
		hosts:   map[string]bool{"127.0.0.1:" + port: true, "localhost:" + port: true},
		origins: map[string]bool{},
	}
	for _, o := range cfg.AllowedOrigins {
		s.origins[normalizeOrigin(o)] = true
	}
	if cfg.Demo != nil {
		s.origins["http://127.0.0.1:"+port] = true
		s.origins["http://localhost:"+port] = true
	}
	return s
}

func normalizeOrigin(o string) string {
	return strings.TrimRight(strings.ToLower(strings.TrimSpace(o)), "/")
}

func (s *server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h := w.Header()
	h.Set("Cache-Control", "no-store")
	h.Set("X-Content-Type-Options", "nosniff")

	if !s.admit(w, r) {
		return
	}

	switch r.URL.Path {
	case "/v1/status":
		allow(w, r, http.MethodGet, s.status)
	case "/v1/certificates":
		allow(w, r, http.MethodGet, s.certificates)
	case "/v1/sign":
		allow(w, r, http.MethodPost, s.sign)
	default:
		if s.cfg.Demo != nil && !strings.HasPrefix(r.URL.Path, "/v1/") {
			s.cfg.Demo.ServeHTTP(w, r)
			return
		}
		writeError(w, http.StatusNotFound, "request.not_found", msgNotFound)
	}
}

// admit applies the host and origin checks and answers CORS preflights. It reports whether the
// request may continue to a route.
func (s *server) admit(w http.ResponseWriter, r *http.Request) bool {
	if !s.hosts[strings.ToLower(r.Host)] {
		writeError(w, http.StatusForbidden, "request.invalid_host", msgInvalidHost)
		return false
	}

	origin := r.Header.Get("Origin")
	if origin == "" {
		// Same-origin navigations and plain tools send no Origin; only reads are allowed that way.
		if r.Method != http.MethodGet {
			writeError(w, http.StatusForbidden, "request.origin_not_allowed", msgOriginNotAllowed)
			return false
		}
		return true
	}
	if !s.origins[normalizeOrigin(origin)] {
		writeError(w, http.StatusForbidden, "request.origin_not_allowed", msgOriginNotAllowed)
		return false
	}

	h := w.Header()
	h.Add("Vary", "Origin")
	h.Set("Access-Control-Allow-Origin", origin)
	if r.Method != http.MethodOptions {
		return true
	}
	h.Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
	h.Set("Access-Control-Allow-Headers", "Content-Type")
	h.Set("Access-Control-Max-Age", "600")
	if r.Header.Get("Access-Control-Request-Private-Network") == "true" {
		h.Set("Access-Control-Allow-Private-Network", "true")
	}
	w.WriteHeader(http.StatusNoContent)
	return false
}

func allow(w http.ResponseWriter, r *http.Request, method string, next http.HandlerFunc) {
	if r.Method != method {
		w.Header().Set("Allow", method)
		writeError(w, http.StatusMethodNotAllowed, "request.method_not_allowed", msgMethodNotAllowed)
		return
	}
	next(w, r)
}

func (s *server) status(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"version":           s.cfg.Version,
		"platformSupported": s.cfg.PlatformSupported,
	})
}
