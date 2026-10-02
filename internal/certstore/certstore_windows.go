//go:build windows

package certstore

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	certKeyProvInfoPropID = 2          // CERT_KEY_PROV_INFO_PROP_ID
	bcryptPadPKCS1        = 0x00000002 // BCRYPT_PAD_PKCS1

	hresultCancelled = syscall.Errno(0x800704C7) // HRESULT_FROM_WIN32(ERROR_CANCELLED)
)

var (
	crypt32         = windows.NewLazySystemDLL("crypt32.dll")
	procGetCertProp = crypt32.NewProc("CertGetCertificateContextProperty")
	ncrypt          = windows.NewLazySystemDLL("ncrypt.dll")
	procSignHash    = ncrypt.NewProc("NCryptSignHash")
	procFreeObject  = ncrypt.NewProc("NCryptFreeObject")

	errClosed = errors.New("certstore: signer is closed")

	hashNames = map[crypto.Hash]string{
		crypto.SHA1:   "SHA1",
		crypto.SHA256: "SHA256",
		crypto.SHA384: "SHA384",
		crypto.SHA512: "SHA512",
	}
)

func freeContext(ctx *windows.CertContext) { _ = windows.CertFreeCertificateContext(ctx) }

// hasKeyProvInfo reports whether the certificate is linked to a private key.
// It only reads a property of the context; the token is not touched.
func hasKeyProvInfo(ctx *windows.CertContext) bool {
	var size uint32
	r, _, _ := procGetCertProp.Call(
		uintptr(unsafe.Pointer(ctx)), certKeyProvInfoPropID, 0, uintptr(unsafe.Pointer(&size)))
	return r != 0
}

func openStore() (windows.Handle, error) {
	name, err := windows.UTF16PtrFromString("MY")
	if err != nil {
		return 0, err
	}
	store, err := windows.CertOpenStore(windows.CERT_STORE_PROV_SYSTEM, 0, 0,
		windows.CERT_SYSTEM_STORE_CURRENT_USER|windows.CERT_STORE_OPEN_EXISTING_FLAG|windows.CERT_STORE_READONLY_FLAG,
		uintptr(unsafe.Pointer(name)))
	runtime.KeepAlive(name) // the wrapper takes a uintptr, which does not keep name reachable
	if err != nil {
		return 0, fmt.Errorf("certstore: open store: %w", err)
	}
	return store, nil
}

// forEach calls fn for every parsable certificate that has a private key. The
// context is only valid during fn; fn stops the walk by returning true.
func forEach(fn func(ctx *windows.CertContext, cert *x509.Certificate) (stop bool)) error {
	store, err := openStore()
	if err != nil {
		return err
	}
	defer func() { _ = windows.CertCloseStore(store, 0) }()

	var ctx *windows.CertContext
	for {
		// Passing the previous context back frees it; only an early stop must free it explicitly.
		ctx, err = windows.CertEnumCertificatesInStore(store, ctx)
		if ctx == nil {
			if err == nil || errors.Is(err, syscall.Errno(windows.CRYPT_E_NOT_FOUND)) {
				return nil
			}
			return fmt.Errorf("certstore: enumerate: %w", err)
		}
		if ctx.EncodedCert == nil || ctx.Length == 0 {
			continue
		}
		// x509 keeps references into its input, which the context owns.
		cert, perr := x509.ParseCertificate(bytes.Clone(unsafe.Slice(ctx.EncodedCert, ctx.Length)))
		if perr != nil || !hasKeyProvInfo(ctx) {
			continue
		}
		if fn(ctx, cert) {
			freeContext(ctx)
			return nil
		}
	}
}

// List returns the certificates in CurrentUser\My that have an associated private key.
func List() ([]Certificate, error) {
	var out []Certificate
	err := forEach(func(_ *windows.CertContext, cert *x509.Certificate) bool {
		out = append(out, Certificate{ID: thumbprint(cert.Raw), Cert: cert})
		return false
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// find returns a new reference to the context of the certificate with the given
// thumbprint; the caller must free it.
func find(id string) (*windows.CertContext, *x509.Certificate, error) {
	var (
		found *windows.CertContext
		cert  *x509.Certificate
	)
	err := forEach(func(ctx *windows.CertContext, c *x509.Certificate) bool {
		if thumbprint(c.Raw) != id {
			return false
		}
		found, cert = windows.CertDuplicateCertificateContext(ctx), c
		return true
	})
	if err != nil {
		return nil, nil, err
	}
	if found == nil {
		return nil, nil, ErrNotFound
	}
	return found, cert, nil
}

type signer struct {
	cert *x509.Certificate

	mu   sync.Mutex // serializes use of key against Close
	key  windows.Handle
	free bool                 // the key handle must be released with NCryptFreeObject
	ctx  *windows.CertContext // keeps a cached key alive; the context owns it
}

// Open acquires the CNG key of the certificate with the given thumbprint.
// The driver shows its PIN dialog when it needs it, which may be on the first Sign.
func Open(id string) (Signer, error) {
	ctx, cert, err := find(strings.ToUpper(strings.TrimSpace(id)))
	if err != nil {
		return nil, err
	}
	defer freeContext(ctx)
	if err := checkKey(cert.PublicKey); err != nil {
		return nil, err
	}
	s, err := acquire(ctx, cert)
	if err != nil {
		return nil, err
	}
	return s, nil
}

func acquire(ctx *windows.CertContext, cert *x509.Certificate) (*signer, error) {
	var (
		key  windows.Handle
		spec uint32
		free bool
	)
	// No CRYPT_ACQUIRE_SILENT_FLAG: the driver must be allowed to show its PIN dialog.
	err := windows.CryptAcquireCertificatePrivateKey(ctx, windows.CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG,
		nil, &key, &spec, &free)
	if err != nil {
		return nil, wrapErr("acquire private key", err)
	}
	s := &signer{cert: cert, key: key, free: free}
	if !free {
		// A handle the caller must not free lives and dies with the context.
		s.ctx = windows.CertDuplicateCertificateContext(ctx)
	}
	return s, nil
}

// wrapErr adds ErrCancelled to err when the user cancelled the token's PIN prompt.
// NCrypt returns its SECURITY_STATUS directly instead of through GetLastError;
// callers pass it as a syscall.Errno.
func wrapErr(op string, err error) error {
	var errno syscall.Errno
	if errors.As(err, &errno) {
		switch errno {
		case syscall.Errno(windows.NTE_USER_CANCELLED), syscall.Errno(windows.SCARD_W_CANCELLED_BY_USER),
			windows.ERROR_CANCELLED, hresultCancelled:
			return fmt.Errorf("certstore: %s: %w: %w", op, ErrCancelled, err)
		}
	}
	return fmt.Errorf("certstore: %s: %w", op, err)
}

func (s *signer) Certificate() *x509.Certificate { return s.cert }

func (s *signer) Public() crypto.PublicKey { return s.cert.PublicKey }

func (s *signer) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.key == 0 {
		return nil
	}
	var err error
	if s.free {
		if r, _, _ := procFreeObject.Call(uintptr(s.key)); r != 0 {
			err = fmt.Errorf("certstore: free key: %w", syscall.Errno(uint32(r)))
		}
	}
	if s.ctx != nil {
		freeContext(s.ctx)
		s.ctx = nil
	}
	s.key = 0
	return err
}

func (s *signer) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if len(digest) == 0 {
		return nil, errors.New("certstore: empty digest")
	}
	if _, ok := s.cert.PublicKey.(*rsa.PublicKey); ok {
		pad, err := rsaPadding(digest, opts)
		if err != nil {
			return nil, err
		}
		return s.signHash(digest, pad, bcryptPadPKCS1)
	}
	raw, err := s.signHash(digest, nil, 0)
	if err != nil {
		return nil, err
	}
	return ecdsaRawToDER(raw)
}

// pkcs1PaddingInfo is BCRYPT_PKCS1_PADDING_INFO.
type pkcs1PaddingInfo struct {
	algID *uint16
}

func rsaPadding(digest []byte, opts crypto.SignerOpts) (*pkcs1PaddingInfo, error) {
	if opts == nil {
		return nil, errors.New("certstore: RSA signing needs the hash in opts")
	}
	if _, ok := opts.(*rsa.PSSOptions); ok {
		return nil, errors.New("certstore: RSA-PSS is not supported")
	}
	hash := opts.HashFunc()
	name, ok := hashNames[hash]
	if !ok {
		return nil, fmt.Errorf("certstore: unsupported hash %v for RSA", hash)
	}
	if len(digest) != hash.Size() {
		return nil, fmt.Errorf("certstore: digest is %d bytes, %v needs %d", len(digest), hash, hash.Size())
	}
	algID, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return nil, err
	}
	return &pkcs1PaddingInfo{algID: algID}, nil
}

// signHash calls NCryptSignHash twice: once to learn the signature size, once to sign.
func (s *signer) signHash(digest []byte, pad *pkcs1PaddingInfo, flags uintptr) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.key == 0 {
		return nil, errClosed
	}

	var n uint32
	call := func(out *byte) error {
		r, _, _ := procSignHash.Call(uintptr(s.key), uintptr(unsafe.Pointer(pad)),
			uintptr(unsafe.Pointer(&digest[0])), uintptr(len(digest)),
			uintptr(unsafe.Pointer(out)), uintptr(n), uintptr(unsafe.Pointer(&n)), flags)
		if r != 0 {
			return wrapErr("NCryptSignHash", syscall.Errno(uint32(r)))
		}
		return nil
	}
	if err := call(nil); err != nil {
		return nil, err
	}
	sig := make([]byte, n)
	if err := call(unsafe.SliceData(sig)); err != nil {
		return nil, err
	}
	return sig[:n], nil
}
