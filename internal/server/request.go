package server

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
)

type signRequest struct {
	CertificateID string            `json:"certificateId"`
	Documents     []documentRequest `json:"documents"`
}

type documentRequest struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Format string `json:"format"`
	Data   string `json:"data"`
}

// readSignRequest decodes and validates the body. On failure it has already written the response.
func readSignRequest(w http.ResponseWriter, r *http.Request) (req signRequest, contents [][]byte, ok bool) {
	reject := func(message string) (signRequest, [][]byte, bool) {
		writeError(w, http.StatusBadRequest, "request.invalid", message)
		return signRequest{}, nil, false
	}

	// Requiring JSON also forces a CORS preflight for cross-origin callers.
	if mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || mt != "application/json" {
		return reject(msgNotJSON)
	}

	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBodyBytes))
	if err := dec.Decode(&req); err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			return reject(msgTooLarge)
		}
		return reject(msgUnreadable)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return reject(msgUnreadable)
	}

	if req.CertificateID == "" || len(req.Documents) == 0 {
		return reject(msgMissingFields)
	}
	contents = make([][]byte, len(req.Documents))
	seen := make(map[string]bool, len(req.Documents))
	for i, d := range req.Documents {
		if d.ID == "" || seen[d.ID] {
			return reject(msgBadDocumentID)
		}
		seen[d.ID] = true
		if d.Format != "udf" && d.Format != "cms" {
			return reject(msgBadFormat)
		}
		data, err := base64.StdEncoding.DecodeString(d.Data)
		if err != nil {
			return reject(msgBadBase64)
		}
		contents[i] = data
	}
	return req, contents, true
}
