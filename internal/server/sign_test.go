package server

import (
	"archive/zip"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"esign/internal/cades"
	"esign/internal/certstore"
)

func TestSignUDFAndCMS(t *testing.T) {
	f := newFixture(t, nil)
	content := "<content>sözleşme</content>"
	udfData := makeUDF(t, content)
	raw := []byte("arbitrary bytes")

	rec := f.post(testOrigin, map[string]any{
		"certificateId": strings.ToLower(f.cert.ID),
		"documents": []any{
			doc("a", "dilekce.udf", "udf", udfData),
			doc("b", "ek.bin", "cms", raw),
		},
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body)
	}
	var resp signResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil || len(resp.Results) != 2 {
		t.Fatalf("body = %s (%v)", rec.Body, err)
	}
	if resp.Results[0].ID != "a" || resp.Results[1].ID != "b" {
		t.Errorf("result order = %+v", resp.Results)
	}

	signedUDF := decode(t, resp.Results[0])
	zr, err := zip.NewReader(bytes.NewReader(signedUDF), int64(len(signedUDF)))
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	var sgn []byte
	for _, e := range zr.File {
		names = append(names, e.Name)
		if e.Name == "sign.sgn" {
			rc, _ := e.Open()
			sgn, _ = io.ReadAll(rc)
			_ = rc.Close()
		}
	}
	if strings.Join(names, ",") != "content.xml,documentproperties.xml,sign.sgn" {
		t.Errorf("entries = %v", names)
	}
	if _, err := cades.Verify(sgn, []byte(content)); err != nil {
		t.Errorf("udf signature does not verify: %v", err)
	}

	certs, err := cades.Verify(decode(t, resp.Results[1]), raw)
	if err != nil || len(certs) != 1 || !certs[0].Equal(f.cert.Cert) {
		t.Errorf("cms signature: certs=%d err=%v", len(certs), err)
	}

	if !f.store.signer.closed {
		t.Error("signer was not closed")
	}
	if f.confirmer.calls != 1 {
		t.Errorf("confirmations = %d, want 1 for the whole batch", f.confirmer.calls)
	}
}

func decode(t *testing.T, r documentResult) []byte {
	t.Helper()
	if r.Error != "" {
		t.Fatalf("document %q failed: %s", r.ID, r.Error)
	}
	data, err := base64.StdEncoding.DecodeString(r.Data)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestSignReportsPerDocumentErrors(t *testing.T) {
	f := newFixture(t, nil)
	signed := func() []byte {
		rec := f.post(testOrigin, map[string]any{"certificateId": "AABBCC", "documents": []any{doc("1", "a.udf", "udf", makeUDF(t, "<c/>"))}})
		var resp signResponse
		_ = json.Unmarshal(rec.Body.Bytes(), &resp)
		return decode(t, resp.Results[0])
	}()

	rec := f.post(testOrigin, map[string]any{
		"certificateId": "AABBCC",
		"documents": []any{
			doc("bad", "x.udf", "udf", []byte("not a zip")),
			doc("again", "y.udf", "udf", signed),
			doc("good", "z.bin", "cms", []byte("ok")),
		},
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body)
	}
	var resp signResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp.Results[0].Error == "" || resp.Results[0].Data != "" {
		t.Errorf("invalid udf result = %+v", resp.Results[0])
	}
	if resp.Results[1].Error == "" || resp.Results[1].Data != "" {
		t.Errorf("already signed result = %+v", resp.Results[1])
	}
	if resp.Results[2].Error != "" || resp.Results[2].Data == "" {
		t.Errorf("good result = %+v; the batch must continue after a failure", resp.Results[2])
	}
}

func TestSignDeclined(t *testing.T) {
	f := newFixture(t, nil)
	f.confirmer.answer = false

	rec := f.post(testOrigin, map[string]any{"certificateId": "AABBCC", "documents": []any{doc("1", "a.bin", "cms", []byte("x"))}})
	assertError(t, rec, 409, "sign.cancelled")
	if f.store.signer.signCalls != 0 {
		t.Error("signed although the user declined")
	}
}

func TestSignCancelledAtPINPrompt(t *testing.T) {
	f := newFixture(t, nil)
	f.store.signer.signErr = certstore.ErrCancelled

	rec := f.post(testOrigin, map[string]any{"certificateId": "AABBCC", "documents": []any{doc("1", "a.bin", "cms", []byte("x")), doc("2", "b.bin", "cms", []byte("y"))}})
	assertError(t, rec, 409, "sign.cancelled")
	if f.store.signer.signCalls != 1 {
		t.Errorf("sign calls = %d, a cancelled PIN prompt must stop the batch", f.store.signer.signCalls)
	}
	if !f.store.signer.closed {
		t.Error("signer was not closed")
	}

	f = newFixture(t, nil)
	f.store.openErr = certstore.ErrCancelled
	assertError(t, f.post(testOrigin, map[string]any{"certificateId": "AABBCC", "documents": []any{doc("1", "a.bin", "cms", []byte("x"))}}), 409, "sign.cancelled")
}

func TestSignCertificateErrors(t *testing.T) {
	f := newFixture(t, nil)
	assertError(t, f.post(testOrigin, map[string]any{"certificateId": "NOPE", "documents": []any{doc("1", "a.bin", "cms", []byte("x"))}}), 404, "certificate.not_found")
	if f.confirmer.calls != 0 {
		t.Error("asked for confirmation for an unknown certificate")
	}

	f.store.openErr = certstore.ErrNotFound
	assertError(t, f.post(testOrigin, map[string]any{"certificateId": "AABBCC", "documents": []any{doc("1", "a.bin", "cms", []byte("x"))}}), 404, "certificate.not_found")

	f.store.openErr = certstore.ErrUnsupportedKey
	assertError(t, f.post(testOrigin, map[string]any{"certificateId": "AABBCC", "documents": []any{doc("1", "a.bin", "cms", []byte("x"))}}), 400, "request.invalid")

	f.store.openErr = errors.New("driver exploded")
	rec := f.post(testOrigin, map[string]any{"certificateId": "AABBCC", "documents": []any{doc("1", "a.bin", "cms", []byte("x"))}})
	assertError(t, rec, 500, "internal")
	if strings.Contains(rec.Body.String(), "driver") {
		t.Error("internal error detail leaked to the page")
	}
}

func TestSignBusy(t *testing.T) {
	f := newFixture(t, nil)
	var inner *httptest.ResponseRecorder
	f.confirmer.duringFn = func() {
		inner = f.post(testOrigin, map[string]any{"certificateId": "AABBCC", "documents": []any{doc("1", "a.bin", "cms", []byte("x"))}})
	}

	rec := f.post(testOrigin, map[string]any{"certificateId": "AABBCC", "documents": []any{doc("1", "a.bin", "cms", []byte("x"))}})
	if rec.Code != http.StatusOK {
		t.Fatalf("outer status = %d: %s", rec.Code, rec.Body)
	}
	assertError(t, inner, 409, "sign.busy")
}

func TestSignInvalidRequests(t *testing.T) {
	f := newFixture(t, nil)
	valid := doc("1", "a.bin", "cms", []byte("x"))

	cases := map[string]request{
		"not json":        {contentType: "application/json", body: "{"},
		"trailing data":   {contentType: "application/json", body: `{"certificateId":"AABBCC","documents":[]} {}`},
		"wrong type":      {contentType: "text/plain", body: "{}"},
		"no content type": {body: "{}"},
		"empty":           {contentType: "application/json", body: "{}"},
	}
	for name, r := range cases {
		r.method, r.path, r.origin = http.MethodPost, "/v1/sign", testOrigin
		t.Run(name, func(t *testing.T) { assertError(t, f.do(r), 400, "request.invalid") })
	}

	bodies := map[string]map[string]any{
		"no certificate": {"documents": []any{valid}},
		"no documents":   {"certificateId": "AABBCC", "documents": []any{}},
		"no id":          {"certificateId": "AABBCC", "documents": []any{doc("", "a", "cms", []byte("x"))}},
		"duplicate id":   {"certificateId": "AABBCC", "documents": []any{valid, valid}},
		"unknown format": {"certificateId": "AABBCC", "documents": []any{doc("1", "a", "pdf", []byte("x"))}},
		"bad base64":     {"certificateId": "AABBCC", "documents": []any{map[string]string{"id": "1", "name": "a", "format": "cms", "data": "!!!"}}},
	}
	for name, body := range bodies {
		t.Run(name, func(t *testing.T) { assertError(t, f.post(testOrigin, body), 400, "request.invalid") })
	}
	if f.confirmer.calls != 0 {
		t.Error("invalid requests must never reach the confirmation window")
	}
}

func TestSignTooLarge(t *testing.T) {
	f := newFixture(t, nil)
	r := request{
		method: http.MethodPost, path: "/v1/sign", origin: testOrigin, contentType: "application/json",
		body: `{"certificateId":"AABBCC","documents":[{"id":"1","format":"cms","data":"` + strings.Repeat("A", maxBodyBytes) + `"}]}`,
	}
	assertError(t, f.do(r), 400, "request.invalid")
}
