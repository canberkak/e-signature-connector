package server

import (
	"encoding/json"
	"net/http"
)

type errorBody struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, errorBody{Code: code, Message: message})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writePlatformUnsupported(w http.ResponseWriter) {
	writeError(w, http.StatusNotImplemented, "platform.unsupported", msgPlatformUnsupported)
}

func writeCancelled(w http.ResponseWriter) {
	writeError(w, http.StatusConflict, "sign.cancelled", msgCancelled)
}

func writeCertificateNotFound(w http.ResponseWriter) {
	writeError(w, http.StatusNotFound, "certificate.not_found", msgCertificateNotFound)
}
