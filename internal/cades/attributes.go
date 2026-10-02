package cades

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"slices"
)

// checkAttributes verifies the signed attributes CAdES-BES relies on: contentType, messageDigest
// over content and signingCertificateV2 naming cert. Other attributes are ignored.
func checkAttributes(attrs asn1.RawValue, cert *x509.Certificate, hash crypto.Hash, content []byte) error {
	list, err := children(attrs)
	if err != nil {
		return fmt.Errorf("cades: malformed signed attributes: %w", err)
	}
	values := make(map[string]asn1.RawValue, len(list))
	for _, a := range list {
		ac, err := sequence(a, "attribute", 2, 2)
		if err != nil {
			return err
		}
		oid, err := parseOID(ac[0], "attribute type")
		if err != nil {
			return err
		}
		vs, err := set(ac[1], "attribute values")
		if err != nil {
			return err
		}
		if len(vs) != 1 {
			return errors.New("cades: attribute must have exactly one value")
		}
		if _, dup := values[oid.String()]; dup {
			return errors.New("cades: duplicate signed attribute")
		}
		values[oid.String()] = vs[0]
	}

	ct, ok := values[oidContentType.String()]
	if !ok {
		return errors.New("cades: contentType attribute missing")
	}
	contentType, err := parseOID(ct, "contentType attribute")
	if err != nil {
		return err
	}
	if !contentType.Equal(oidData) {
		return errors.New("cades: contentType attribute is not id-data")
	}

	md, ok := values[oidMessageDigest.String()]
	if !ok {
		return errors.New("cades: messageDigest attribute missing")
	}
	if !isOctetString(md) {
		return errors.New("cades: malformed messageDigest attribute")
	}
	if !bytes.Equal(md.Bytes, digest(hash, content)) {
		return errors.New("cades: content does not match the messageDigest")
	}

	sc, ok := values[oidSigningCertificateV2.String()]
	if !ok {
		return errors.New("cades: signingCertificateV2 attribute missing")
	}
	return checkSigningCertificate(sc, cert)
}

// checkSigningCertificate checks that the first ESSCertIDv2 (RFC 5035) identifies cert.
func checkSigningCertificate(sc asn1.RawValue, cert *x509.Certificate) error {
	top, err := sequence(sc, "signingCertificateV2", 1, 2)
	if err != nil {
		return err
	}
	ids, err := sequence(top[0], "signingCertificateV2 certs", 1, unbounded)
	if err != nil {
		return err
	}
	id, err := sequence(ids[0], "ESSCertIDv2", 1, 3)
	if err != nil {
		return err
	}

	hash := crypto.SHA256 // the DEFAULT when hashAlgorithm is absent
	if isConstructed(id[0], asn1.ClassUniversal, asn1.TagSequence) {
		oid, err := parseAlgorithm(id[0], "ESSCertIDv2 hash algorithm")
		if err != nil {
			return err
		}
		h, ok := hashForOID(oid)
		if !ok {
			return fmt.Errorf("cades: unsupported ESSCertIDv2 hash algorithm %v", oid)
		}
		hash = h
		id = id[1:]
	}
	if len(id) < 1 || len(id) > 2 || !isOctetString(id[0]) {
		return errors.New("cades: malformed ESSCertIDv2")
	}
	if !bytes.Equal(id[0].Bytes, digest(hash, cert.Raw)) {
		return errors.New("cades: signing certificate hash mismatch")
	}
	if len(id) == 1 {
		return nil
	}
	return checkIssuerSerial(id[1], cert)
}

func checkIssuerSerial(rv asn1.RawValue, cert *x509.Certificate) error {
	is, err := sequence(rv, "issuerSerial", 2, 2)
	if err != nil {
		return err
	}
	names, err := sequence(is[0], "issuerSerial issuer", 1, unbounded)
	if err != nil {
		return err
	}
	matched := slices.ContainsFunc(names, func(n asn1.RawValue) bool {
		return isConstructed(n, asn1.ClassContextSpecific, 4) && bytes.Equal(n.Bytes, cert.RawIssuer)
	})
	if !matched {
		return errors.New("cades: issuerSerial issuer mismatch")
	}
	serial, err := parseInt(is[1], "issuerSerial serial number")
	if err != nil {
		return err
	}
	if serial.Cmp(cert.SerialNumber) != 0 {
		return errors.New("cades: issuerSerial serial number mismatch")
	}
	return nil
}
