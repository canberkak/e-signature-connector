package certstore

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"math/big"
	"strings"
	"testing"
)

func TestECDSARawToDER(t *testing.T) {
	curves := []elliptic.Curve{elliptic.P256(), elliptic.P384(), elliptic.P521()}
	for _, curve := range curves {
		t.Run(curve.Params().Name, func(t *testing.T) {
			size := (curve.Params().BitSize + 7) / 8
			r := make([]byte, size) // leading zeros and a high bit set exercise DER integer rules
			s := make([]byte, size)
			r[size-1] = 0x01
			s[0] = 0xFF
			raw := append(append([]byte(nil), r...), s...)

			der, err := ecdsaRawToDER(raw)
			if err != nil {
				t.Fatal(err)
			}
			var sig struct{ R, S *big.Int }
			rest, err := asn1.Unmarshal(der, &sig)
			if err != nil || len(rest) != 0 {
				t.Fatalf("not a single DER SEQUENCE: %v, rest %d", err, len(rest))
			}
			if sig.R.Cmp(new(big.Int).SetBytes(r)) != 0 || sig.S.Cmp(new(big.Int).SetBytes(s)) != 0 {
				t.Fatalf("r/s mismatch: %v %v", sig.R, sig.S)
			}
		})
	}
}

func TestECDSARawToDERVerifies(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte("message"))
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	raw := append(r.FillBytes(make([]byte, 48)), s.FillBytes(make([]byte, 48))...)
	der, err := ecdsaRawToDER(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !ecdsa.VerifyASN1(&key.PublicKey, digest[:], der) {
		t.Fatal("converted signature does not verify")
	}
}

func TestECDSARawToDERRejectsMalformed(t *testing.T) {
	for _, raw := range [][]byte{nil, {}, {1, 2, 3}} {
		if _, err := ecdsaRawToDER(raw); err == nil {
			t.Errorf("expected an error for %v", raw)
		}
	}
}

func TestThumbprint(t *testing.T) {
	raw := []byte("not really a certificate")
	sum := sha1.Sum(raw)
	want := strings.ToUpper(hex.EncodeToString(sum[:]))
	got := thumbprint(raw)
	if got != want || len(got) != 40 {
		t.Fatalf("thumbprint = %q, want %q", got, want)
	}
}

func TestCheckKey(t *testing.T) {
	p224, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p256, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	if err := checkKey(&p256.PublicKey); err != nil {
		t.Errorf("P-256: %v", err)
	}
	if err := checkKey(&rsaKey.PublicKey); err != nil {
		t.Errorf("RSA: %v", err)
	}
	if err := checkKey(&p224.PublicKey); !errors.Is(err, ErrUnsupportedKey) {
		t.Errorf("P-224: got %v, want ErrUnsupportedKey", err)
	}
	if err := checkKey(struct{}{}); !errors.Is(err, ErrUnsupportedKey) {
		t.Errorf("unknown key: got %v, want ErrUnsupportedKey", err)
	}
}
