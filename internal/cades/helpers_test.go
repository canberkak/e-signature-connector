package cades

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"slices"
	"testing"
	"time"
)

var signTime = time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)

type keyCase struct {
	name   string
	hash   crypto.Hash
	sigOID asn1.ObjectIdentifier
	newKey func(t testing.TB) crypto.Signer
}

var keyCases = []keyCase{
	{"P-256", crypto.SHA256, oidECDSAWithSHA256, func(t testing.TB) crypto.Signer { return genEC(t, elliptic.P256()) }},
	{"P-384", crypto.SHA384, oidECDSAWithSHA384, func(t testing.TB) crypto.Signer { return genEC(t, elliptic.P384()) }},
	{"P-521", crypto.SHA512, oidECDSAWithSHA512, func(t testing.TB) crypto.Signer { return genEC(t, elliptic.P521()) }},
	{"RSA", crypto.SHA256, oidSHA256WithRSA, func(t testing.TB) crypto.Signer {
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		return k
	}},
}

func genEC(t testing.TB, c elliptic.Curve) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(c, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func selfSigned(t testing.TB, signer crypto.Signer, cn string, serial int64) *x509.Certificate {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: cn, SerialNumber: "10000000146", Country: []string{"TR"}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageContentCommitment,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, signer.Public(), signer)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func mustSign(t *testing.T, content []byte, signer crypto.Signer, cert *x509.Certificate) []byte {
	t.Helper()
	out, err := SignDetached(content, signer, cert, signTime)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func flip(b []byte, i int) []byte {
	out := slices.Clone(b)
	out[i] ^= 0xFF
	return out
}

func oidDER(t *testing.T, oid asn1.ObjectIdentifier) []byte {
	t.Helper()
	var b builder
	out := b.marshal(oid)
	if b.err != nil {
		t.Fatal(b.err)
	}
	return out
}

func algDER(t *testing.T, oid asn1.ObjectIdentifier) []byte {
	t.Helper()
	var b builder
	out := b.algorithm(oid, false)
	if b.err != nil {
		t.Fatal(b.err)
	}
	return out
}

func mustTLV(t *testing.T, b []byte) asn1.RawValue {
	t.Helper()
	rv, err := parseSingle(b, "test input")
	if err != nil {
		t.Fatal(err)
	}
	return rv
}

func mustChildren(t *testing.T, rv asn1.RawValue) []asn1.RawValue {
	t.Helper()
	c, err := children(rv)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func mustOID(t *testing.T, rv asn1.RawValue) asn1.ObjectIdentifier {
	t.Helper()
	oid, err := parseOID(rv, "oid")
	if err != nil {
		t.Fatal(err)
	}
	return oid
}

func signerInfoOf(t *testing.T, sig []byte) []asn1.RawValue {
	t.Helper()
	top := mustChildren(t, mustTLV(t, sig))
	sd := mustChildren(t, mustTLV(t, top[1].Bytes))
	return mustChildren(t, mustChildren(t, sd[len(sd)-1])[0])
}
