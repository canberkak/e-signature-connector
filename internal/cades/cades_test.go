package cades

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/asn1"
	"math/big"
	"slices"
	"testing"
)

func TestDigestFor(t *testing.T) {
	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		pub  crypto.PublicKey
		want crypto.Hash
		fail bool
	}{
		{name: "P-256", pub: genEC(t, elliptic.P256()).Public(), want: crypto.SHA256},
		{name: "P-384", pub: genEC(t, elliptic.P384()).Public(), want: crypto.SHA384},
		{name: "P-521", pub: genEC(t, elliptic.P521()).Public(), want: crypto.SHA512},
		{name: "RSA", pub: keyCases[3].newKey(t).Public(), want: crypto.SHA256},
		{name: "P-224", pub: genEC(t, elliptic.P224()).Public(), fail: true},
		{name: "Ed25519", pub: edKey.Public(), fail: true},
		{name: "not a key", pub: "not a key", fail: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := DigestFor(tc.pub)
			if tc.fail {
				if err == nil {
					t.Fatalf("accepted, got %v", got)
				}
				return
			}
			if err != nil || got != tc.want {
				t.Fatalf("got %v, %v; want %v", got, err, tc.want)
			}
		})
	}
}

func TestSignVerifyRoundTrip(t *testing.T) {
	content := []byte("<content>hello</content>")
	for _, tc := range keyCases {
		t.Run(tc.name, func(t *testing.T) {
			signer := tc.newKey(t)
			cert := selfSigned(t, signer, "Test "+tc.name, 42)
			sig := mustSign(t, content, signer, cert)

			certs, err := Verify(sig, content)
			if err != nil {
				t.Fatal(err)
			}
			if len(certs) != 1 || !bytes.Equal(certs[0].Raw, cert.Raw) {
				t.Fatalf("unexpected signer certificates: %d", len(certs))
			}
			if _, err := Verify(sig, append([]byte("x"), content...)); err == nil {
				t.Error("different content verified")
			}
		})
	}
}

func TestEmptyContent(t *testing.T) {
	signer := genEC(t, elliptic.P256())
	cert := selfSigned(t, signer, "Empty", 1)
	sig := mustSign(t, nil, signer, cert)
	if _, err := Verify(sig, []byte{}); err != nil {
		t.Fatal(err)
	}
}

func TestSignDetachedRejectsBadInput(t *testing.T) {
	a, b := genEC(t, elliptic.P256()), genEC(t, elliptic.P256())
	cert := selfSigned(t, a, "A", 1)
	tests := []struct {
		name   string
		signer crypto.Signer
		cert   *x509.Certificate
	}{
		{"key does not match the certificate", b, cert},
		{"nil signer", nil, cert},
		{"nil certificate", a, nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := SignDetached([]byte("x"), tc.signer, tc.cert, signTime); err == nil {
				t.Error("accepted")
			}
		})
	}
}

func TestStructure(t *testing.T) {
	content := []byte("structure")
	for _, tc := range keyCases {
		t.Run(tc.name, func(t *testing.T) {
			signer := tc.newKey(t)
			cert := selfSigned(t, signer, "Structure", 0x1234567)
			sig := mustSign(t, content, signer, cert)
			digestAlg := algDER(t, digestOIDs[tc.hash])

			top := mustChildren(t, mustTLV(t, sig))
			if len(top) != 2 || !mustOID(t, top[0]).Equal(oidSignedData) {
				t.Fatal("not a ContentInfo(signedData)")
			}
			sd := mustChildren(t, mustTLV(t, top[1].Bytes))
			if len(sd) != 5 {
				t.Fatalf("SignedData has %d fields, want 5 (no CRLs)", len(sd))
			}
			if !bytes.Equal(sd[0].FullBytes, []byte{2, 1, 1}) {
				t.Error("SignedData version is not 1")
			}
			if algs := mustChildren(t, sd[1]); len(algs) != 1 || !bytes.Equal(algs[0].FullBytes, digestAlg) {
				t.Error("digestAlgorithms is not the single explicit digest algorithm")
			}
			if encap := mustChildren(t, sd[2]); len(encap) != 1 || !mustOID(t, encap[0]).Equal(oidData) {
				t.Error("encapContentInfo must be id-data without eContent")
			}
			if sd[3].Class != asn1.ClassContextSpecific || sd[3].Tag != 0 {
				t.Fatal("certificates is not [0]")
			}
			if certs := mustChildren(t, sd[3]); len(certs) != 1 || !bytes.Equal(certs[0].FullBytes, cert.Raw) {
				t.Error("certificates must hold only the signer certificate")
			}

			infos := mustChildren(t, sd[4])
			if len(infos) != 1 {
				t.Fatal("want one SignerInfo")
			}
			si := mustChildren(t, infos[0])
			if len(si) != 6 {
				t.Fatalf("SignerInfo has %d fields, want 6 (no unsigned attributes)", len(si))
			}
			if !bytes.Equal(si[0].FullBytes, []byte{2, 1, 1}) {
				t.Error("SignerInfo version is not 1")
			}
			sid := mustChildren(t, si[1])
			if !bytes.Equal(sid[0].FullBytes, cert.RawIssuer) {
				t.Error("sid issuer mismatch")
			}
			var serial *big.Int
			if _, err := asn1.Unmarshal(sid[1].FullBytes, &serial); err != nil || serial.Cmp(cert.SerialNumber) != 0 {
				t.Error("sid serial mismatch")
			}
			if !bytes.Equal(si[2].FullBytes, digestAlg) {
				t.Error("SignerInfo digestAlgorithm mismatch")
			}
			if si[3].FullBytes[0] != 0xA0 {
				t.Errorf("signed attributes tag = %#x, want 0xA0", si[3].FullBytes[0])
			}
			if got := mustOID(t, mustChildren(t, si[4])[0]); !got.Equal(tc.sigOID) {
				t.Errorf("signature algorithm = %v, want %v", got, tc.sigOID)
			}

			attrs := mustChildren(t, si[3])
			if len(attrs) != 4 {
				t.Fatalf("got %d signed attributes, want 4", len(attrs))
			}
			encodings := make([][]byte, len(attrs))
			var oids []string
			for i, a := range attrs {
				encodings[i] = a.FullBytes
				oids = append(oids, mustOID(t, mustChildren(t, a)[0]).String())
			}
			if !slices.IsSortedFunc(encodings, bytes.Compare) {
				t.Error("signed attributes are not sorted by encoding")
			}
			wantOIDs := []string{oidContentType.String(), oidMessageDigest.String(), oidSigningTime.String(), oidSigningCertificateV2.String()}
			slices.Sort(oids)
			slices.Sort(wantOIDs)
			if !slices.Equal(oids, wantOIDs) {
				t.Errorf("attribute types = %v", oids)
			}

			attr := func(oid asn1.ObjectIdentifier) asn1.RawValue {
				for _, a := range attrs {
					c := mustChildren(t, a)
					if mustOID(t, c[0]).Equal(oid) {
						return mustChildren(t, c[1])[0]
					}
				}
				t.Fatalf("attribute %v missing", oid)
				return asn1.RawValue{}
			}
			if st := attr(oidSigningTime); st.Tag != asn1.TagUTCTime {
				t.Errorf("signingTime tag = %d, want UTCTime", st.Tag)
			} else if got := string(st.Bytes); got != "260304050607Z" {
				t.Errorf("signingTime = %q", got)
			}
			ess := mustChildren(t, mustChildren(t, mustChildren(t, attr(oidSigningCertificateV2))[0])[0])
			if len(ess) != 3 {
				t.Fatalf("ESSCertIDv2 has %d fields, want 3", len(ess))
			}
			if !bytes.Equal(ess[0].FullBytes, digestAlg) {
				t.Error("ESSCertIDv2 hashAlgorithm must be explicit and equal to the digest")
			}
			if !bytes.Equal(ess[1].Bytes, digest(tc.hash, cert.Raw)) {
				t.Error("certHash mismatch")
			}
			is := mustChildren(t, ess[2])
			names := mustChildren(t, is[0])
			if len(names) != 1 || names[0].FullBytes[0] != 0xA4 || !bytes.Equal(names[0].Bytes, cert.RawIssuer) {
				t.Error("issuerSerial issuer is not GeneralNames[directoryName(issuer)]")
			}
			if _, err := asn1.Unmarshal(is[1].FullBytes, &serial); err != nil || serial.Cmp(cert.SerialNumber) != 0 {
				t.Error("issuerSerial serial mismatch")
			}
		})
	}
}
