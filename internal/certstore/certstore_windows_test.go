//go:build windows

package certstore

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/windows"
)

func powershell(script string) (string, error) {
	out, err := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", script).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("powershell: %w\n%s", err, out)
	}
	return strings.TrimSpace(string(out)), nil
}

// createTestCert creates a software, non-exportable self-signed certificate. The
// cleanup is registered before the certificate exists, so a failure at any point
// cannot leave it or its key behind.
func createTestCert(t *testing.T, keyParams string) string {
	t.Helper()
	suffix := make([]byte, 6)
	if _, err := rand.Read(suffix); err != nil {
		t.Fatal(err)
	}
	subject := "esign-connector-test-" + hex.EncodeToString(suffix)
	t.Cleanup(func() {
		// -DeleteKey only exists when the item is addressed by an explicit path.
		_, err := powershell(`Get-ChildItem Cert:\CurrentUser\My | Where-Object Subject -eq 'CN=` + subject + `' | ` +
			`ForEach-Object { Remove-Item -Path ('Cert:\CurrentUser\My\' + $_.Thumbprint) -DeleteKey -Force }`)
		if err != nil {
			t.Error(err)
		}
	})
	thumb, err := powershell(`(New-SelfSignedCertificate -Subject 'CN=` + subject + `' ` + keyParams +
		` -KeyExportPolicy NonExportable -KeyUsage DigitalSignature -CertStoreLocation Cert:\CurrentUser\My).Thumbprint`)
	if err != nil {
		t.Fatal(err)
	}
	if len(thumb) != 40 {
		t.Fatalf("unexpected thumbprint %q", thumb)
	}
	return strings.ToUpper(thumb)
}

func TestSignWithStoreCertificate(t *testing.T) {
	if os.Getenv("ESIGN_INTEGRATION") != "1" {
		t.Skip("set ESIGN_INTEGRATION=1 to create a test certificate in the user certificate store")
	}

	t.Run("ECDSA P-384", func(t *testing.T) {
		id := createTestCert(t, `-KeyAlgorithm ECDSA_nistP384`)
		s := openListed(t, id)
		pub, ok := s.Public().(*ecdsa.PublicKey)
		if !ok {
			t.Fatalf("public key is %T", s.Public())
		}
		digest := sha512.Sum384([]byte("hello"))
		for range 2 { // one signer serves a whole batch
			sig, err := s.Sign(rand.Reader, digest[:], crypto.SHA384)
			if err != nil {
				t.Fatal(err)
			}
			if !ecdsa.VerifyASN1(pub, digest[:], sig) {
				t.Fatal("signature does not verify")
			}
		}

		if err := s.Close(); err != nil {
			t.Fatal(err)
		}
		if _, err := s.Sign(rand.Reader, digest[:], crypto.SHA384); err == nil {
			t.Error("Sign after Close succeeded")
		}
	})

	t.Run("RSA 2048", func(t *testing.T) {
		id := createTestCert(t, `-KeyAlgorithm RSA -KeyLength 2048`)
		s := openListed(t, id)
		pub, ok := s.Public().(*rsa.PublicKey)
		if !ok {
			t.Fatalf("public key is %T", s.Public())
		}
		digest := sha256.Sum256([]byte("hello"))
		sig, err := s.Sign(rand.Reader, digest[:], crypto.SHA256)
		if err != nil {
			t.Fatal(err)
		}
		if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], sig); err != nil {
			t.Fatal(err)
		}

		if _, err := s.Sign(rand.Reader, digest[:], crypto.MD5); err == nil {
			t.Error("MD5 should be rejected")
		}
		if _, err := s.Sign(rand.Reader, digest[:], crypto.SHA384); err == nil {
			t.Error("a SHA-256 digest with SHA384 opts should be rejected")
		}
		if _, err := s.Sign(rand.Reader, digest[:], &rsa.PSSOptions{Hash: crypto.SHA256}); err == nil {
			t.Error("PSS should be rejected")
		}
	})
}

// openListed opens the certificate and closes the signer when the test ends.
func openListed(t *testing.T, id string) Signer {
	t.Helper()
	certs, err := List()
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, c := range certs {
		if c.ID == id {
			found = true
			if c.Cert == nil || thumbprint(c.Cert.Raw) != id {
				t.Fatal("listed certificate does not match its id")
			}
		}
	}
	if !found {
		t.Fatalf("certificate %s not listed", id)
	}
	s, err := Open(id)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := s.Close(); err != nil {
			t.Error(err)
		}
	})
	return s
}

func TestOpenUnknownID(t *testing.T) {
	if _, err := Open("0000000000000000000000000000000000000000"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("got %v, want ErrNotFound", err)
	}
}

func TestWrapErrCancelled(t *testing.T) {
	cancelled := []syscall.Errno{
		syscall.Errno(windows.NTE_USER_CANCELLED),
		syscall.Errno(windows.SCARD_W_CANCELLED_BY_USER),
		windows.ERROR_CANCELLED,
		hresultCancelled,
	}
	for _, errno := range cancelled {
		err := wrapErr("op", errno)
		if !errors.Is(err, ErrCancelled) || !errors.Is(err, errno) {
			t.Errorf("wrapErr(%#x) = %v, want ErrCancelled wrapping the cause", uintptr(errno), err)
		}
	}
	if err := wrapErr("op", syscall.Errno(windows.NTE_BAD_KEY)); errors.Is(err, ErrCancelled) {
		t.Errorf("NTE_BAD_KEY reported as cancelled: %v", err)
	}
}
