package cades

import (
	"bytes"
	"crypto"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"math/big"
	mrand "math/rand/v2"
	"slices"
	"strings"
	"testing"
)

func TestTamper(t *testing.T) {
	content := []byte("tamper me")
	signer := genEC(t, elliptic.P256())
	cert := selfSigned(t, signer, "Tamper", 7)
	sig := mustSign(t, content, signer, cert)

	t.Run("content", func(t *testing.T) {
		if _, err := Verify(sig, []byte("tamper mE")); err == nil {
			t.Fatal("accepted")
		}
	})

	t.Run("signature", func(t *testing.T) {
		raw := signerInfoOf(t, sig)[5].Bytes
		bad := bytes.Replace(sig, raw, flip(raw, len(raw)-1), 1)
		if bytes.Equal(bad, sig) {
			t.Fatal("test did not modify the signature")
		}
		if _, err := Verify(bad, content); err == nil {
			t.Fatal("accepted")
		}
	})

	t.Run("signed attributes", func(t *testing.T) {
		bad := bytes.Replace(sig, []byte("260304050607Z"), []byte("260304050608Z"), 1)
		if bytes.Equal(bad, sig) {
			t.Fatal("signing time not found")
		}
		if _, err := Verify(bad, content); err == nil {
			t.Fatal("accepted")
		}
	})

	t.Run("signature algorithm does not fit the digest", func(t *testing.T) {
		want, other := oidDER(t, oidECDSAWithSHA256), oidDER(t, oidECDSAWithSHA384)
		// The embedded certificate carries the same OID, so patch the last occurrence: the SignerInfo's.
		i := bytes.LastIndex(sig, want)
		if i < 0 {
			t.Fatal("signature algorithm not found")
		}
		bad := slices.Clone(sig)
		copy(bad[i:], other)
		if _, err := Verify(bad, content); err == nil {
			t.Fatal("accepted")
		}
	})

	t.Run("wrong certificate", func(t *testing.T) {
		var other *x509.Certificate
		for range 64 {
			c := selfSigned(t, genEC(t, elliptic.P256()), "Tamper", 7)
			if len(c.Raw) == len(cert.Raw) {
				other = c
				break
			}
		}
		if other == nil {
			t.Skip("could not generate a same-length certificate")
		}
		bad := bytes.Replace(sig, cert.Raw, other.Raw, 1)
		if _, err := Verify(bad, content); err == nil {
			t.Fatal("accepted")
		}
	})

	t.Run("signer certificate is not embedded", func(t *testing.T) {
		other := selfSigned(t, genEC(t, elliptic.P256()), "Other", 8)
		var b builder
		out, err := b.assemble(signer, other, crypto.SHA256, b.signedAttributes(content, cert, crypto.SHA256, signTime))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := Verify(out, content); err == nil {
			t.Fatal("accepted")
		}
	})
}

func TestSignedAttributeChecks(t *testing.T) {
	content := []byte("attributes")
	signer := genEC(t, elliptic.P256())
	cert := selfSigned(t, signer, "Attrs", 9)
	other := selfSigned(t, genEC(t, elliptic.P256()), "Another issuer", 9)
	certHash := sha256.Sum256(cert.Raw)

	// good returns the attributes in the order contentType, signingTime, messageDigest, signingCertificateV2.
	good := func(b *builder) [][]byte { return b.signedAttributes(content, cert, crypto.SHA256, signTime) }
	replace := func(b *builder, i int, attr []byte) [][]byte {
		attrs := good(b)
		attrs[i] = attr
		return attrs
	}
	remove := func(b *builder, i int) [][]byte { return slices.Delete(good(b), i, i+1) }
	signingCert := func(b *builder, id []byte) []byte {
		return b.attribute(oidSigningCertificateV2, b.seq(b.seq(id)))
	}
	build := func(attrs func(b *builder) [][]byte) []byte {
		var b builder
		out, err := b.assemble(signer, cert, crypto.SHA256, attrs(&b))
		if err != nil {
			t.Fatal(err)
		}
		return out
	}

	if _, err := Verify(build(good), content); err != nil {
		t.Fatalf("control case failed: %v", err)
	}

	rejected := []struct {
		name  string
		attrs func(b *builder) [][]byte
	}{
		{"no contentType", func(b *builder) [][]byte { return remove(b, 0) }},
		{"no messageDigest", func(b *builder) [][]byte { return remove(b, 2) }},
		{"no signingCertificateV2", func(b *builder) [][]byte { return remove(b, 3) }},
		{"no attributes at all", func(b *builder) [][]byte { return nil }},
		{"contentType is not data", func(b *builder) [][]byte {
			return replace(b, 0, b.attribute(oidContentType, b.marshal(oidSignedData)))
		}},
		{"wrong messageDigest", func(b *builder) [][]byte {
			return replace(b, 2, b.attribute(oidMessageDigest, b.marshal(make([]byte, 32))))
		}},
		{"duplicate attribute", func(b *builder) [][]byte {
			attrs := good(b)
			return append(attrs, attrs[0])
		}},
		{"certHash of another certificate", func(b *builder) [][]byte {
			return replace(b, 3, b.signedAttributes(content, other, crypto.SHA256, signTime)[3])
		}},
		{"issuerSerial serial differs", func(b *builder) [][]byte {
			id := b.seq(b.algorithm(oidSHA256, false), b.marshal(certHash[:]),
				b.seq(b.seq(b.context(4, cert.RawIssuer)), b.marshal(big.NewInt(1234))))
			return replace(b, 3, signingCert(b, id))
		}},
		{"issuerSerial issuer differs", func(b *builder) [][]byte {
			id := b.seq(b.algorithm(oidSHA256, false), b.marshal(certHash[:]),
				b.seq(b.seq(b.context(4, other.RawIssuer)), b.marshal(cert.SerialNumber)))
			return replace(b, 3, signingCert(b, id))
		}},
		{"unsupported ESSCertIDv2 hash algorithm", func(b *builder) [][]byte {
			id := b.seq(b.algorithm(oidSHA256WithRSA, false), b.marshal(certHash[:]))
			return replace(b, 3, signingCert(b, id))
		}},
	}
	for _, tc := range rejected {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Verify(build(tc.attrs), content); err == nil {
				t.Fatal("accepted")
			}
		})
	}

	t.Run("absent ESSCertIDv2 hashAlgorithm defaults to SHA-256", func(t *testing.T) {
		sig := build(func(b *builder) [][]byte {
			return replace(b, 3, signingCert(b, b.seq(b.marshal(certHash[:]))))
		})
		if _, err := Verify(sig, content); err != nil {
			t.Fatal(err)
		}
	})
}

func TestVerifyRejectsMalformed(t *testing.T) {
	content := []byte("malformed")
	signer := genEC(t, elliptic.P256())
	cert := selfSigned(t, signer, "Malformed", 10)
	sig := mustSign(t, content, signer, cert)

	tests := []struct {
		name string
		data []byte
	}{
		{"trailing data", append(slices.Clone(sig), 0)},
		{"empty input", nil},
		{"indefinite length", []byte(strings.Repeat("\x30\x80", 100))},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Verify(tc.data, content); err == nil {
				t.Error("accepted")
			}
		})
	}
}

func TestVerifyHostileInput(t *testing.T) {
	content := []byte("hostile")
	signer := genEC(t, elliptic.P256())
	cert := selfSigned(t, signer, "Hostile", 11)
	sig := mustSign(t, content, signer, cert)

	for n := range len(sig) {
		if _, err := Verify(sig[:n], content); err == nil {
			t.Fatalf("truncated to %d bytes verified", n)
		}
	}

	// Only absence of panics is asserted: some bytes, such as the certificate's own signature, are
	// not covered by the CMS signature.
	rng := mrand.New(mrand.NewPCG(1, 2))
	for i := range sig {
		for _, mask := range []byte{0xFF, 0x01, 0x80} {
			mutated := slices.Clone(sig)
			mutated[i] ^= mask
			_, _ = Verify(mutated, content)
		}
		mutated := slices.Clone(sig)
		mutated[i] = byte(rng.UintN(256))
		_, _ = Verify(mutated, content)
	}
	for range 2000 {
		junk := make([]byte, rng.IntN(300))
		for i := range junk {
			junk[i] = byte(rng.UintN(256))
		}
		_, _ = Verify(junk, content)
	}
}

func FuzzVerify(f *testing.F) {
	content := []byte("fuzz")
	signer := genEC(f, elliptic.P256())
	cert := selfSigned(f, signer, "Fuzz", 12)
	sig, err := SignDetached(content, signer, cert, signTime)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(sig)
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = Verify(data, content)
	})
}
