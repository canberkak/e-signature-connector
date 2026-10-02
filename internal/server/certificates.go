package server

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"log"
	"net/http"
	"time"

	"esign/internal/certstore"
)

var oidQCStatements = []int{1, 3, 6, 1, 5, 5, 7, 1, 3}

type certificateInfo struct {
	ID             string `json:"id"`
	Subject        string `json:"subject"`
	IdentityNumber string `json:"identityNumber"`
	Issuer         string `json:"issuer"`
	NotBefore      string `json:"notBefore"`
	NotAfter       string `json:"notAfter"`
	KeyAlgorithm   string `json:"keyAlgorithm"`
	Qualified      bool   `json:"qualified"`
	Valid          bool   `json:"valid"`
}

func (s *server) certificates(w http.ResponseWriter, _ *http.Request) {
	certs, ok := s.listCertificates(w)
	if !ok {
		return
	}
	now := s.cfg.Now()
	infos := make([]certificateInfo, 0, len(certs))
	for _, c := range certs {
		infos = append(infos, describe(c, now))
	}
	writeJSON(w, http.StatusOK, infos)
}

func (s *server) listCertificates(w http.ResponseWriter) ([]certstore.Certificate, bool) {
	if !s.cfg.PlatformSupported {
		writePlatformUnsupported(w)
		return nil, false
	}
	certs, err := s.cfg.Store.List()
	if errors.Is(err, errors.ErrUnsupported) {
		writePlatformUnsupported(w)
		return nil, false
	}
	if err != nil {
		log.Printf("list certificates: %v", err)
		writeError(w, http.StatusInternalServerError, "internal", msgListFailed)
		return nil, false
	}
	return certs, true
}

func describe(c certstore.Certificate, now time.Time) certificateInfo {
	cert := c.Cert
	return certificateInfo{
		ID:             c.ID,
		Subject:        commonName(cert.Subject),
		IdentityNumber: cert.Subject.SerialNumber,
		Issuer:         commonName(cert.Issuer),
		NotBefore:      cert.NotBefore.UTC().Format(time.RFC3339),
		NotAfter:       cert.NotAfter.UTC().Format(time.RFC3339),
		KeyAlgorithm:   keyAlgorithm(cert.PublicKey),
		Qualified:      hasQCStatements(cert),
		Valid:          withinValidity(cert, now) && canSign(cert),
	}
}

func commonName(n pkix.Name) string {
	if n.CommonName != "" {
		return n.CommonName
	}
	return n.String()
}

func keyAlgorithm(pub crypto.PublicKey) string {
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		return "ECDSA " + k.Curve.Params().Name
	case *rsa.PublicKey:
		return "RSA"
	}
	return "unknown"
}

func hasQCStatements(cert *x509.Certificate) bool {
	for _, e := range cert.Extensions {
		if e.Id.Equal(oidQCStatements) {
			return true
		}
	}
	return false
}

func withinValidity(cert *x509.Certificate, now time.Time) bool {
	return !now.Before(cert.NotBefore) && !now.After(cert.NotAfter)
}

// A certificate without a keyUsage extension places no restriction.
func canSign(cert *x509.Certificate) bool {
	return cert.KeyUsage == 0 || cert.KeyUsage&(x509.KeyUsageDigitalSignature|x509.KeyUsageContentCommitment) != 0
}
