package cades

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"slices"
)

// parsedSignedData is the part of a SignedData that signer verification needs.
type parsedSignedData struct {
	digestAlgs  []asn1.ObjectIdentifier
	certs       []*x509.Certificate
	signerInfos []asn1.RawValue
}

// Verify checks a detached SignedData against content and returns the signer certificates.
// It verifies the math and the signed attributes, not the certificate chain or revocation.
func Verify(signedData, content []byte) ([]*x509.Certificate, error) {
	sd, err := parseSignedData(signedData)
	if err != nil {
		return nil, err
	}
	signers := make([]*x509.Certificate, 0, len(sd.signerInfos))
	for _, si := range sd.signerInfos {
		cert, err := sd.verifySigner(si, content)
		if err != nil {
			return nil, err
		}
		signers = append(signers, cert)
	}
	return signers, nil
}

func parseSignedData(der []byte) (*parsedSignedData, error) {
	root, err := parseSingle(der, "ContentInfo")
	if err != nil {
		return nil, err
	}
	top, err := sequence(root, "ContentInfo", 2, 2)
	if err != nil {
		return nil, err
	}
	oid, err := parseOID(top[0], "contentType")
	if err != nil {
		return nil, err
	}
	if !oid.Equal(oidSignedData) {
		return nil, errors.New("cades: not a SignedData")
	}
	if !isConstructed(top[1], asn1.ClassContextSpecific, 0) {
		return nil, errors.New("cades: malformed ContentInfo content")
	}
	inner, err := parseSingle(top[1].Bytes, "SignedData")
	if err != nil {
		return nil, err
	}
	// version, digestAlgorithms, encapContentInfo, [0] certificates, [1] crls, signerInfos
	sd, err := sequence(inner, "SignedData", 4, 6)
	if err != nil {
		return nil, err
	}
	if err := checkVersion1(sd[0], "SignedData"); err != nil {
		return nil, err
	}

	algs, err := set(sd[1], "digestAlgorithms")
	if err != nil {
		return nil, err
	}
	parsed := &parsedSignedData{}
	for _, a := range algs {
		o, err := parseAlgorithm(a, "digest algorithm")
		if err != nil {
			return nil, err
		}
		parsed.digestAlgs = append(parsed.digestAlgs, o)
	}

	if err := checkDetachedData(sd[2]); err != nil {
		return nil, err
	}

	rest := sd[3:]
	if isConstructed(rest[0], asn1.ClassContextSpecific, 0) {
		if parsed.certs, err = parseCertificates(rest[0]); err != nil {
			return nil, err
		}
		rest = rest[1:]
	}
	if len(rest) > 0 && isConstructed(rest[0], asn1.ClassContextSpecific, 1) {
		rest = rest[1:]
	}
	if len(rest) != 1 {
		return nil, errors.New("cades: malformed SignedData")
	}
	if parsed.signerInfos, err = set(rest[0], "signerInfos"); err != nil {
		return nil, err
	}
	if len(parsed.signerInfos) == 0 {
		return nil, errors.New("cades: no signer")
	}
	return parsed, nil
}

func checkDetachedData(encap asn1.RawValue) error {
	c, err := sequence(encap, "encapContentInfo", 1, unbounded)
	if err != nil {
		return err
	}
	oid, err := parseOID(c[0], "eContentType")
	if err != nil {
		return err
	}
	if !oid.Equal(oidData) {
		return errors.New("cades: unsupported eContentType")
	}
	if len(c) != 1 {
		return errors.New("cades: signature is not detached")
	}
	return nil
}

// parseCertificates skips certificate choices other than a plain Certificate.
func parseCertificates(rv asn1.RawValue) ([]*x509.Certificate, error) {
	items, err := children(rv)
	if err != nil {
		return nil, fmt.Errorf("cades: malformed certificates: %w", err)
	}
	var certs []*x509.Certificate
	for _, item := range items {
		if !isConstructed(item, asn1.ClassUniversal, asn1.TagSequence) {
			continue
		}
		cert, err := x509.ParseCertificate(item.FullBytes)
		if err != nil {
			return nil, fmt.Errorf("cades: malformed certificate: %w", err)
		}
		certs = append(certs, cert)
	}
	return certs, nil
}

func (sd *parsedSignedData) verifySigner(si asn1.RawValue, content []byte) (*x509.Certificate, error) {
	// version, sid, digestAlgorithm, [0] signedAttrs, signatureAlgorithm, signature, [1] unsignedAttrs
	c, err := sequence(si, "SignerInfo", 5, 7)
	if err != nil {
		return nil, err
	}
	if err := checkVersion1(c[0], "SignerInfo"); err != nil {
		return nil, err
	}
	cert, err := sd.findSigner(c[1])
	if err != nil {
		return nil, err
	}

	digestOID, err := parseAlgorithm(c[2], "signer digest algorithm")
	if err != nil {
		return nil, err
	}
	hash, ok := hashForOID(digestOID)
	if !ok {
		return nil, fmt.Errorf("cades: unsupported digest algorithm %v", digestOID)
	}
	if !slices.ContainsFunc(sd.digestAlgs, digestOID.Equal) {
		return nil, errors.New("cades: signer digest algorithm missing from digestAlgorithms")
	}

	if !isConstructed(c[3], asn1.ClassContextSpecific, 0) {
		return nil, errors.New("cades: signed attributes missing")
	}
	if len(c) < 6 || len(c) == 7 && !isConstructed(c[6], asn1.ClassContextSpecific, 1) {
		return nil, errors.New("cades: malformed SignerInfo")
	}
	sigOID, err := parseAlgorithm(c[4], "signature algorithm")
	if err != nil {
		return nil, err
	}
	if !isOctetString(c[5]) {
		return nil, errors.New("cades: malformed signature")
	}

	if err := checkAttributes(c[3], cert, hash, content); err != nil {
		return nil, err
	}

	// The signature covers the attributes as a SET (0x31), not under their [0] IMPLICIT tag.
	d := hash.New()
	d.Write([]byte{0x31})
	d.Write(c[3].FullBytes[1:])
	if err := verifySignature(cert.PublicKey, sigOID, hash, d.Sum(nil), c[5].Bytes); err != nil {
		return nil, err
	}
	return cert, nil
}

func (sd *parsedSignedData) findSigner(sid asn1.RawValue) (*x509.Certificate, error) {
	if !isConstructed(sid, asn1.ClassUniversal, asn1.TagSequence) {
		return nil, errors.New("cades: only issuerAndSerialNumber signer identifiers are supported")
	}
	c, err := sequence(sid, "issuerAndSerialNumber", 2, 2)
	if err != nil {
		return nil, err
	}
	serial, err := parseInt(c[1], "serial number")
	if err != nil {
		return nil, err
	}
	for _, cert := range sd.certs {
		if cert.SerialNumber.Cmp(serial) == 0 && bytes.Equal(cert.RawIssuer, c[0].FullBytes) {
			return cert, nil
		}
	}
	return nil, errors.New("cades: signer certificate not found in the signature")
}

func verifySignature(pub crypto.PublicKey, sigAlg asn1.ObjectIdentifier, hash crypto.Hash, hashed, sig []byte) error {
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		if !sigAlg.Equal(ecdsaSignatureOIDs[hash]) {
			return fmt.Errorf("cades: signature algorithm %v does not fit an ECDSA key and the digest", sigAlg)
		}
		if !ecdsa.VerifyASN1(k, hashed, sig) {
			return errors.New("cades: signature is invalid")
		}
		return nil
	case *rsa.PublicKey:
		if !sigAlg.Equal(rsaSignatureOIDs[hash]) && !sigAlg.Equal(oidRSAEncryption) {
			return fmt.Errorf("cades: signature algorithm %v does not fit an RSA key and the digest", sigAlg)
		}
		if err := rsa.VerifyPKCS1v15(k, hash, hashed, sig); err != nil {
			return fmt.Errorf("cades: signature is invalid: %w", err)
		}
		return nil
	}
	return fmt.Errorf("cades: unsupported key type %T", pub)
}
