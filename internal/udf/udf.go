// Package udf signs UYAP UDF documents: a ZIP whose content.xml is covered by a detached sign.sgn.
package udf

import (
	"archive/zip"
	"bytes"
	"errors"
	"fmt"
	"io"
)

const (
	contentName   = "content.xml"
	signatureName = "sign.sgn"

	// maxContentSize bounds what Content decompresses, so a zip bomb cannot exhaust memory.
	maxContentSize = 50 << 20
)

var (
	// ErrAlreadySigned is returned by Sign when the UDF already contains sign.sgn.
	ErrAlreadySigned = errors.New("udf: document is already signed")
	// ErrNotUDF is returned when the data is not a well-formed UDF archive.
	ErrNotUDF = errors.New("udf: not a UDF document")
)

// archive is a UDF ZIP that passed open's checks.
type archive struct {
	*zip.Reader
	content *zip.File
	signed  bool
}

// Content returns the bytes that get signed (content.xml).
func Content(udf []byte) ([]byte, error) {
	a, err := open(udf)
	if err != nil {
		return nil, err
	}
	return a.readContent()
}

// Sign returns a copy of the UDF with sign.sgn added; every other entry is copied unchanged and in order.
func Sign(udf []byte, signContent func(content []byte) ([]byte, error)) ([]byte, error) {
	a, err := open(udf)
	if err != nil {
		return nil, err
	}
	if a.signed {
		return nil, ErrAlreadySigned
	}
	content, err := a.readContent()
	if err != nil {
		return nil, err
	}
	signature, err := signContent(content)
	if err != nil {
		return nil, err
	}

	var out bytes.Buffer
	zw := zip.NewWriter(&out)
	if err := zw.SetComment(a.Comment); err != nil {
		return nil, fmt.Errorf("udf: copying the archive comment: %w", err)
	}
	for _, f := range a.File {
		if err := copyRaw(zw, f); err != nil {
			return nil, fmt.Errorf("udf: copying %q: %w", f.Name, err)
		}
	}
	w, err := zw.CreateHeader(&zip.FileHeader{Name: signatureName, Method: zip.Deflate, Modified: a.content.Modified})
	if err != nil {
		return nil, fmt.Errorf("udf: adding %s: %w", signatureName, err)
	}
	if _, err := w.Write(signature); err != nil {
		return nil, fmt.Errorf("udf: adding %s: %w", signatureName, err)
	}
	if err := zw.Close(); err != nil {
		return nil, fmt.Errorf("udf: finishing the archive: %w", err)
	}
	return out.Bytes(), nil
}

// open reads the archive and rejects anything that is not an unambiguous UDF: duplicate entry
// names would let a reader and the signer disagree about which content.xml is signed.
func open(udf []byte) (*archive, error) {
	zr, err := zip.NewReader(bytes.NewReader(udf), int64(len(udf)))
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrNotUDF, err)
	}
	a := &archive{Reader: zr}
	seen := make(map[string]bool, len(zr.File))
	for _, f := range zr.File {
		if seen[f.Name] {
			return nil, fmt.Errorf("%w: duplicate entry %q", ErrNotUDF, f.Name)
		}
		seen[f.Name] = true
		switch f.Name {
		case contentName:
			a.content = f
		case signatureName:
			a.signed = true
		}
	}
	if a.content == nil {
		return nil, fmt.Errorf("%w: %s is missing", ErrNotUDF, contentName)
	}
	return a, nil
}

func (a *archive) readContent() ([]byte, error) {
	if a.content.UncompressedSize64 > maxContentSize {
		return nil, fmt.Errorf("%w: %s is too large", ErrNotUDF, contentName)
	}
	rc, err := a.content.Open()
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrNotUDF, err)
	}
	defer func() { _ = rc.Close() }()
	// The declared size is attacker-controlled, so the read itself is bounded too.
	data, err := io.ReadAll(io.LimitReader(rc, maxContentSize+1))
	if err != nil {
		return nil, fmt.Errorf("%w: reading %s: %w", ErrNotUDF, contentName, err)
	}
	if len(data) > maxContentSize {
		return nil, fmt.Errorf("%w: %s is too large", ErrNotUDF, contentName)
	}
	return data, nil
}

// copyRaw transfers the entry's compressed bytes and header as they are.
func copyRaw(zw *zip.Writer, f *zip.File) error {
	raw, err := f.OpenRaw()
	if err != nil {
		return err
	}
	header := f.FileHeader
	w, err := zw.CreateRaw(&header)
	if err != nil {
		return err
	}
	_, err = io.Copy(w, raw)
	return err
}
