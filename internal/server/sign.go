package server

import (
	"encoding/base64"
	"errors"
	"log"
	"net/http"
	"strings"
	"time"

	"esign/internal/cades"
	"esign/internal/certstore"
	"esign/internal/udf"
)

type signResponse struct {
	Results []documentResult `json:"results"`
}

type documentResult struct {
	ID    string `json:"id"`
	Data  string `json:"data,omitempty"`
	Error string `json:"error,omitempty"`
}

func (s *server) sign(w http.ResponseWriter, r *http.Request) {
	req, contents, ok := readSignRequest(w, r)
	if !ok {
		return
	}
	if !s.cfg.PlatformSupported {
		writePlatformUnsupported(w)
		return
	}

	if !s.signing.TryLock() {
		writeError(w, http.StatusConflict, "sign.busy", msgBusy)
		return
	}
	defer s.signing.Unlock()

	chosen, ok := s.findCertificate(w, req.CertificateID)
	if !ok {
		return
	}
	if !s.cfg.Confirmer.Confirm(confirmTitle, confirmMessage(r.Header.Get("Origin"), chosen, req.Documents)) {
		writeCancelled(w)
		return
	}
	signer, ok := s.openSigner(w, chosen.ID)
	if !ok {
		return
	}
	defer func() { _ = signer.Close() }()

	signingTime := s.cfg.Now().UTC().Truncate(time.Second)
	results := make([]documentResult, len(req.Documents))
	for i, d := range req.Documents {
		results[i].ID = d.ID
		out, err := signDocument(signer, d.Format, contents[i], signingTime)
		switch {
		case errors.Is(err, certstore.ErrCancelled):
			writeCancelled(w)
			return
		case err != nil:
			results[i].Error = documentError(err)
		default:
			results[i].Data = base64.StdEncoding.EncodeToString(out)
		}
	}
	writeJSON(w, http.StatusOK, signResponse{Results: results})
}

func (s *server) findCertificate(w http.ResponseWriter, id string) (certstore.Certificate, bool) {
	certs, ok := s.listCertificates(w)
	if !ok {
		return certstore.Certificate{}, false
	}
	for _, c := range certs {
		if strings.EqualFold(c.ID, id) {
			return c, true
		}
	}
	writeCertificateNotFound(w)
	return certstore.Certificate{}, false
}

func (s *server) openSigner(w http.ResponseWriter, id string) (certstore.Signer, bool) {
	signer, err := s.cfg.Store.Open(id)
	switch {
	case err == nil:
		return signer, true
	case errors.Is(err, certstore.ErrCancelled):
		writeCancelled(w)
	case errors.Is(err, certstore.ErrNotFound):
		writeCertificateNotFound(w)
	case errors.Is(err, certstore.ErrUnsupportedKey):
		writeError(w, http.StatusBadRequest, "request.invalid", msgUnsupportedKey)
	default:
		log.Printf("open certificate: %v", err)
		writeError(w, http.StatusInternalServerError, "internal", msgKeyAccessFailed)
	}
	return nil, false
}

func signDocument(signer certstore.Signer, format string, data []byte, signingTime time.Time) ([]byte, error) {
	sign := func(content []byte) ([]byte, error) {
		return cades.SignDetached(content, signer, signer.Certificate(), signingTime)
	}
	if format == "udf" {
		return udf.Sign(data, sign)
	}
	return sign(data)
}

func documentError(err error) string {
	switch {
	case errors.Is(err, udf.ErrNotUDF):
		return msgNotUDF
	case errors.Is(err, udf.ErrAlreadySigned):
		return msgAlreadySigned
	}
	log.Printf("sign document: %v", err)
	return msgSignFailed
}
