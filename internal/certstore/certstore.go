// Package certstore lists the certificates in the Windows user store and signs
// with their CNG keys. The private key stays in the token or key provider; the
// PIN is only ever requested by the driver.
package certstore

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"math/big"
	"strings"
)

// Certificate is a certificate in CurrentUser\My that has an associated private key.
type Certificate struct {
	ID   string // SHA-1 thumbprint, upper-case hex (as Windows shows it)
	Cert *x509.Certificate
}

// Signer is a crypto.Signer backed by a CNG key handle. Sign(rand, digest, opts):
// ECDSA -> ASN.1 DER SEQUENCE{r,s}; RSA -> PKCS#1 v1.5 for opts.HashFunc().
// Keep it open for a whole batch so the token asks for the PIN once.
type Signer interface {
	crypto.Signer
	Certificate() *x509.Certificate
	Close() error
}

var (
	// ErrNotFound means no certificate with the given id has a private key in the store.
	ErrNotFound = errors.New("certstore: certificate not found")
	// ErrUnsupportedKey means the key is neither RSA nor ECDSA P-256/P-384/P-521.
	ErrUnsupportedKey = errors.New("certstore: unsupported key type")
	// ErrCancelled means the user cancelled the token's PIN prompt.
	ErrCancelled = errors.New("certstore: cancelled by user")
)

func thumbprint(raw []byte) string {
	sum := sha1.Sum(raw)
	return strings.ToUpper(hex.EncodeToString(sum[:]))
}

func checkKey(pub crypto.PublicKey) error {
	switch k := pub.(type) {
	case *rsa.PublicKey:
		return nil
	case *ecdsa.PublicKey:
		switch k.Curve {
		case elliptic.P256(), elliptic.P384(), elliptic.P521():
			return nil
		}
	}
	return ErrUnsupportedKey
}

// ecdsaRawToDER converts CNG's fixed-size r||s signature to ASN.1 DER SEQUENCE{r,s}.
func ecdsaRawToDER(raw []byte) ([]byte, error) {
	if len(raw) == 0 || len(raw)%2 != 0 {
		return nil, errors.New("certstore: malformed ECDSA signature")
	}
	half := len(raw) / 2
	return asn1.Marshal(struct{ R, S *big.Int }{
		new(big.Int).SetBytes(raw[:half]),
		new(big.Int).SetBytes(raw[half:]),
	})
}
