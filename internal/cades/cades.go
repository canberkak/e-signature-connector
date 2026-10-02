// Package cades builds and verifies detached CAdES-BES signatures in the shape UYAP uses.
package cades

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	_ "crypto/sha256" // crypto.Hash.New panics unless the hash is linked in; DigestFor and Verify use all three
	_ "crypto/sha512"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"slices"
	"time"
)

var (
	oidData                 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	oidSignedData           = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	oidContentType          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 3}
	oidMessageDigest        = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}
	oidSigningTime          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 5}
	oidSigningCertificateV2 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 47}

	oidSHA256 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidSHA384 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}
	oidSHA512 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}

	oidECDSAWithSHA256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
	oidECDSAWithSHA384 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 3}
	oidECDSAWithSHA512 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 4}

	oidRSAEncryption = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
	oidSHA256WithRSA = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}
	oidSHA384WithRSA = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 12}
	oidSHA512WithRSA = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 13}
)

var (
	digestOIDs = map[crypto.Hash]asn1.ObjectIdentifier{
		crypto.SHA256: oidSHA256,
		crypto.SHA384: oidSHA384,
		crypto.SHA512: oidSHA512,
	}
	ecdsaSignatureOIDs = map[crypto.Hash]asn1.ObjectIdentifier{
		crypto.SHA256: oidECDSAWithSHA256,
		crypto.SHA384: oidECDSAWithSHA384,
		crypto.SHA512: oidECDSAWithSHA512,
	}
	rsaSignatureOIDs = map[crypto.Hash]asn1.ObjectIdentifier{
		crypto.SHA256: oidSHA256WithRSA,
		crypto.SHA384: oidSHA384WithRSA,
		crypto.SHA512: oidSHA512WithRSA,
	}
)

func hashForOID(oid asn1.ObjectIdentifier) (crypto.Hash, bool) {
	for h, o := range digestOIDs {
		if o.Equal(oid) {
			return h, true
		}
	}
	return 0, false
}

func digest(h crypto.Hash, data []byte) []byte {
	d := h.New()
	d.Write(data)
	return d.Sum(nil)
}

// DigestFor picks the digest the signature uses for a key.
func DigestFor(pub crypto.PublicKey) (crypto.Hash, error) {
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		switch k.Curve {
		case elliptic.P256():
			return crypto.SHA256, nil
		case elliptic.P384():
			return crypto.SHA384, nil
		case elliptic.P521():
			return crypto.SHA512, nil
		}
		return 0, errors.New("cades: unsupported elliptic curve")
	case *rsa.PublicKey:
		return crypto.SHA256, nil
	}
	return 0, fmt.Errorf("cades: unsupported key type %T", pub)
}

// builder accumulates the first DER encoding error so the assembly code stays linear.
type builder struct{ err error }

func (b *builder) marshal(v any) []byte {
	out, err := asn1.Marshal(v)
	if err != nil && b.err == nil {
		b.err = err
	}
	return out
}

func (b *builder) constructed(class, tag int, parts ...[]byte) []byte {
	return b.marshal(asn1.RawValue{Class: class, Tag: tag, IsCompound: true, Bytes: bytes.Join(parts, nil)})
}

func (b *builder) seq(parts ...[]byte) []byte {
	return b.constructed(asn1.ClassUniversal, asn1.TagSequence, parts...)
}

func (b *builder) set(parts ...[]byte) []byte {
	return b.constructed(asn1.ClassUniversal, asn1.TagSet, parts...)
}

func (b *builder) context(tag int, parts ...[]byte) []byte {
	return b.constructed(asn1.ClassContextSpecific, tag, parts...)
}

func (b *builder) algorithm(oid asn1.ObjectIdentifier, withNull bool) []byte {
	if withNull {
		return b.seq(b.marshal(oid), b.marshal(asn1.NullRawValue))
	}
	return b.seq(b.marshal(oid))
}

func (b *builder) attribute(oid asn1.ObjectIdentifier, value []byte) []byte {
	return b.seq(b.marshal(oid), b.set(value))
}

func (b *builder) signedAttributes(content []byte, cert *x509.Certificate, hash crypto.Hash, signingTime time.Time) [][]byte {
	issuerSerial := b.seq(b.seq(b.context(4, cert.RawIssuer)), b.marshal(cert.SerialNumber))
	essCertID := b.seq(b.algorithm(digestOIDs[hash], false), b.marshal(digest(hash, cert.Raw)), issuerSerial)

	return [][]byte{
		b.attribute(oidContentType, b.marshal(oidData)),
		b.attribute(oidSigningTime, b.marshal(signingTime.UTC())),
		b.attribute(oidMessageDigest, b.marshal(digest(hash, content))),
		b.attribute(oidSigningCertificateV2, b.seq(b.seq(essCertID))),
	}
}

func (b *builder) signatureAlgorithm(pub crypto.PublicKey, hash crypto.Hash) []byte {
	if _, ok := pub.(*rsa.PublicKey); ok {
		return b.algorithm(rsaSignatureOIDs[hash], true)
	}
	return b.algorithm(ecdsaSignatureOIDs[hash], false)
}

// assemble signs the attributes and wraps everything into ContentInfo. Attributes are sorted here;
// the signature covers the SET encoding (tag 0x31) while the SignerInfo carries it as [0] IMPLICIT.
func (b *builder) assemble(signer crypto.Signer, cert *x509.Certificate, hash crypto.Hash, attrs [][]byte) ([]byte, error) {
	attrs = slices.Clone(attrs)
	slices.SortFunc(attrs, bytes.Compare)

	signature, err := signer.Sign(rand.Reader, digest(hash, b.set(attrs...)), hash)
	if err != nil {
		return nil, fmt.Errorf("cades: signing failed: %w", err)
	}

	digestAlg := b.algorithm(digestOIDs[hash], false)
	signerInfo := b.seq(
		b.marshal(1),
		b.seq(cert.RawIssuer, b.marshal(cert.SerialNumber)),
		digestAlg,
		b.context(0, attrs...),
		b.signatureAlgorithm(cert.PublicKey, hash),
		b.marshal(signature),
	)
	signedData := b.seq(
		b.marshal(1),
		b.set(digestAlg),
		b.seq(b.marshal(oidData)),
		b.context(0, cert.Raw),
		b.set(signerInfo),
	)
	out := b.seq(b.marshal(oidSignedData), b.context(0, signedData))
	if b.err != nil {
		return nil, fmt.Errorf("cades: encoding failed: %w", b.err)
	}
	return out, nil
}

// SignDetached builds a detached CAdES-BES SignedData over content.
func SignDetached(content []byte, signer crypto.Signer, cert *x509.Certificate, signingTime time.Time) ([]byte, error) {
	if signer == nil || cert == nil || len(cert.Raw) == 0 {
		return nil, errors.New("cades: signer and certificate are required")
	}
	hash, err := DigestFor(cert.PublicKey)
	if err != nil {
		return nil, err
	}
	pub, ok := signer.Public().(interface{ Equal(crypto.PublicKey) bool })
	if !ok || !pub.Equal(cert.PublicKey) {
		return nil, errors.New("cades: signer key does not match the certificate")
	}

	var b builder
	out, err := b.assemble(signer, cert, hash, b.signedAttributes(content, cert, hash, signingTime))
	if err != nil {
		return nil, err
	}
	if _, err := Verify(out, content); err != nil {
		return nil, fmt.Errorf("cades: the signer produced an invalid signature: %w", err)
	}
	return out, nil
}
