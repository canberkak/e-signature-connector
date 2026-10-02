package udf

import (
	"archive/zip"
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"math/big"
	"strings"
	"testing"
	"time"

	"esign/internal/cades"
)

type entry struct {
	name   string
	data   string
	method uint16
}

var sampleEntries = []entry{
	{"content.xml", "<?xml version=\"1.0\"?><template><content>" + strings.Repeat("Dear Court ", 50) + "</content></template>", zip.Deflate},
	{"documentproperties.xml", "<properties><author>Test</author></properties>", zip.Store},
	{"extra/readme.txt", "kept as is", zip.Deflate},
}

func build(t *testing.T, entries []entry) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for i, e := range entries {
		w, err := zw.CreateHeader(&zip.FileHeader{
			Name:     e.name,
			Method:   e.method,
			Modified: time.Date(2025, 1, 2, 3, 4, 5+2*i, 0, time.UTC),
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte(e.data)); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func reader(t *testing.T, data []byte) *zip.Reader {
	t.Helper()
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	return zr
}

func rawBytes(t *testing.T, f *zip.File) []byte {
	t.Helper()
	r, err := f.OpenRaw()
	if err != nil {
		t.Fatal(err)
	}
	b, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func testSigner(t *testing.T) (*ecdsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(5),
		Subject:      pkix.Name{CommonName: "UDF Test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return key, cert
}

func TestContent(t *testing.T) {
	got, err := Content(build(t, sampleEntries))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != sampleEntries[0].data {
		t.Errorf("content = %q", got)
	}
}

func TestSignRoundTrip(t *testing.T) {
	src := build(t, sampleEntries)
	key, cert := testSigner(t)

	var signed []byte
	out, err := Sign(src, func(content []byte) ([]byte, error) {
		sig, err := cades.SignDetached(content, key, cert, time.Now())
		signed = content
		return sig, err
	})
	if err != nil {
		t.Fatal(err)
	}
	if string(signed) != sampleEntries[0].data {
		t.Error("signer received something other than content.xml")
	}

	in, res := reader(t, src), reader(t, out)
	if len(res.File) != len(in.File)+1 {
		t.Fatalf("got %d entries, want %d", len(res.File), len(in.File)+1)
	}
	for i, f := range in.File {
		g := res.File[i]
		if g.Name != f.Name || g.Method != f.Method || !g.Modified.Equal(f.Modified) || g.CRC32 != f.CRC32 ||
			g.CompressedSize64 != f.CompressedSize64 || g.UncompressedSize64 != f.UncompressedSize64 {
			t.Errorf("entry %d header changed: %+v -> %+v", i, f.FileHeader, g.FileHeader)
		}
		if !bytes.Equal(rawBytes(t, f), rawBytes(t, g)) {
			t.Errorf("entry %q bytes changed", f.Name)
		}
	}

	last := res.File[len(res.File)-1]
	if last.Name != "sign.sgn" {
		t.Fatalf("last entry = %q", last.Name)
	}
	if !last.Modified.Equal(in.File[0].Modified) {
		t.Errorf("sign.sgn modified = %v, want the content.xml time %v", last.Modified, in.File[0].Modified)
	}
	rc, err := last.Open()
	if err != nil {
		t.Fatal(err)
	}
	sig, err := io.ReadAll(rc)
	_ = rc.Close()
	if err != nil {
		t.Fatal(err)
	}
	certs, err := cades.Verify(sig, []byte(sampleEntries[0].data))
	if err != nil || len(certs) != 1 {
		t.Fatalf("sign.sgn does not verify: %v", err)
	}

	if content, err := Content(out); err != nil || string(content) != sampleEntries[0].data {
		t.Errorf("Content of signed UDF: %v", err)
	}
}

func TestSignKeepsComment(t *testing.T) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	if err := zw.SetComment("original comment"); err != nil {
		t.Fatal(err)
	}
	w, err := zw.Create("content.xml")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte("<a/>")); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	out, err := Sign(buf.Bytes(), func([]byte) ([]byte, error) { return []byte("sig"), nil })
	if err != nil {
		t.Fatal(err)
	}
	if got := reader(t, out).Comment; got != "original comment" {
		t.Errorf("comment = %q", got)
	}
}

func TestSignAlreadySigned(t *testing.T) {
	src := build(t, append(sampleEntries[:2:2], entry{"sign.sgn", "old", zip.Store}))
	called := false
	_, err := Sign(src, func([]byte) ([]byte, error) { called = true; return nil, nil })
	if !errors.Is(err, ErrAlreadySigned) {
		t.Fatalf("err = %v", err)
	}
	if called {
		t.Error("signer was called for an already signed UDF")
	}
}

func TestNotUDF(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{"not a zip", []byte("this is not a zip file")},
		{"empty", nil},
		{"no content.xml", build(t, []entry{{"documentproperties.xml", "<p/>", zip.Store}})},
		{"empty zip", build(t, nil)},
		{"wrong case", build(t, []entry{{"Content.xml", "<a/>", zip.Store}})},
		{"nested content.xml", build(t, []entry{{"dir/content.xml", "<a/>", zip.Store}})},
		{"duplicate content.xml", build(t, []entry{{"content.xml", "<a/>", zip.Store}, {"content.xml", "<b/>", zip.Store}})},
		{"duplicate other entry", build(t, []entry{{"content.xml", "<a/>", zip.Store}, {"x", "1", zip.Store}, {"x", "2", zip.Store}})},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Content(tc.data); !errors.Is(err, ErrNotUDF) {
				t.Errorf("Content err = %v", err)
			}
			_, err := Sign(tc.data, func([]byte) ([]byte, error) { t.Error("signer called"); return nil, nil })
			if !errors.Is(err, ErrNotUDF) {
				t.Errorf("Sign err = %v", err)
			}
		})
	}
}

func TestSignPropagatesSignerError(t *testing.T) {
	want := errors.New("declined")
	_, err := Sign(build(t, sampleEntries), func([]byte) ([]byte, error) { return nil, want })
	if !errors.Is(err, want) {
		t.Errorf("err = %v", err)
	}
}

func TestContentSizeLimit(t *testing.T) {
	oversized := entry{"content.xml", strings.Repeat("a", maxContentSize+1), zip.Deflate}
	data := build(t, []entry{oversized})
	if len(data) > 1<<20 {
		t.Fatalf("test archive unexpectedly large: %d", len(data))
	}
	if _, err := Content(data); !errors.Is(err, ErrNotUDF) {
		t.Errorf("oversized content.xml: err = %v", err)
	}

	atLimit := entry{"content.xml", strings.Repeat("a", maxContentSize), zip.Deflate}
	if got, err := Content(build(t, []entry{atLimit})); err != nil || len(got) != maxContentSize {
		t.Errorf("content.xml at the limit: len=%d err=%v", len(got), err)
	}
}

func TestContentLyingHeader(t *testing.T) {
	data := build(t, []entry{{"content.xml", strings.Repeat("a", maxContentSize+10), zip.Deflate}})
	// Shrink the declared uncompressed size in both the local and central headers to 1 byte.
	zr := reader(t, data)
	declared := zr.File[0].UncompressedSize64
	needle := []byte{byte(declared), byte(declared >> 8), byte(declared >> 16), byte(declared >> 24)}
	patched := bytes.ReplaceAll(data, needle, []byte{1, 0, 0, 0})
	if bytes.Equal(patched, data) {
		t.Fatal("declared size not found")
	}
	if _, err := Content(patched); !errors.Is(err, ErrNotUDF) {
		t.Errorf("err = %v", err)
	}
}
