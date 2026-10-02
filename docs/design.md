# E-Signature Connector — design

A single Windows executable that lets a web application sign documents with the e-signature (e-imza) token plugged into the user's PC. No installer, no runtime: the user downloads `esign-connector.exe` from the web app and runs it.

## Why it exists

Browsers cannot use a smart card's private key to sign documents: Web Crypto only sees browser-generated keys, WebUSB blocks the smart-card class, and the Web Smart Card API is limited to Isolated Web Apps. Every Turkish web e-signature flow (e-Devlet, banks, UYAP) therefore relies on a local component. This is ours, kept as small as possible.

## Principles

- **The private key never leaves the token, and the PIN never passes through our code.** We ask Windows (CNG) to sign a digest; the token's driver shows its own PIN dialog.
- **The user sees what they sign in a native window**, not only in the web page: before any signing, a Windows dialog lists the certificate and the documents and asks for confirmation. A compromised or spoofed page cannot sign silently.
- **Only allowed web origins can talk to it.** Requests from any other site are rejected server-side (not only by CORS).
- **Card-brand independent.** Certificates and keys come from the Windows certificate store (`CurrentUser\My`) through CNG, which every Turkish e-imza driver populates. PKCS#11 is a possible later fallback.

## Signature format (UYAP-compatible CAdES-BES)

Taken from a real UYAP UDF (`sign.sgn`):

- CMS `SignedData`, version 1, **detached** (`eContentType` = `id-data`, `eContent` absent).
- One `SignerInfo` per signer, version 1, `sid` = `issuerAndSerialNumber`.
- Digest: SHA-384 for P-384 keys (the UYAP sample: `ecdsa-with-SHA384`); SHA-256 for P-256 and RSA keys; SHA-512 for P-521.
- Signed attributes (DER SET, sorted): `contentType` (id-data), `signingTime` (UTCTime), `messageDigest`, `signingCertificateV2` with one `ESSCertIDv2` = { `hashAlgorithm` written explicitly (same as the digest), `certHash` of the DER certificate, `issuerSerial` = { `GeneralNames[directoryName(issuer)]`, `serialNumber` } }.
- No unsigned attributes (no timestamp).
- `certificates` contains only the signer certificate.
- Signature algorithm: `ecdsa-with-SHA384/256/512` (ECDSA signature DER-encoded as `SEQUENCE{r,s}`), or `sha256WithRSAEncryption` (PKCS#1 v1.5).

UDF: a ZIP with `content.xml`, `documentproperties.xml` and, once signed, `sign.sgn`. The signed content is the exact bytes of `content.xml`.

## Packages

```
cmd/connector         main: flags, single instance, protocol registration, start server, idle exit
internal/certstore    Windows certificate store + CNG signing (crypto.Signer)
internal/cades        CAdES-BES detached SignedData builder and verifier
internal/udf          sign a UDF: content.xml → sign.sgn
internal/server       localhost HTTP API, origin/host checks, confirmation flow
internal/winui        native Windows dialogs and HKCU URL protocol registration
demo/                 a test page the connector can serve itself (--demo)
```

### `internal/certstore`

```go
type Certificate struct {
    ID   string            // SHA-1 thumbprint, upper-case hex (as Windows shows it)
    Cert *x509.Certificate
}

// List returns the certificates in CurrentUser\My that have an associated private key.
func List() ([]Certificate, error)

// Signer is a crypto.Signer backed by a CNG key handle. Sign(rand, digest, opts):
// ECDSA → ASN.1 DER SEQUENCE{r,s}; RSA → PKCS#1 v1.5 for opts.HashFunc().
// Keep it open for a whole batch so the token asks for the PIN once.
type Signer interface {
    crypto.Signer
    Certificate() *x509.Certificate
    Close() error
}

func Open(id string) (Signer, error)

var ErrNotFound, ErrUnsupportedKey, ErrCancelled error // ErrCancelled: the user cancelled the token's PIN prompt
```
On non-Windows builds `List`/`Open` return `errors.ErrUnsupported`.

### `internal/cades`

```go
// DigestFor picks the digest the signature uses for a key (see "Signature format").
func DigestFor(pub crypto.PublicKey) (crypto.Hash, error)

// SignDetached builds a detached CAdES-BES SignedData over content.
func SignDetached(content []byte, signer crypto.Signer, cert *x509.Certificate, signingTime time.Time) ([]byte, error)

// Verify checks a detached SignedData against content and returns the signer certificates.
// It verifies the math and the signed attributes, not the certificate chain or revocation.
func Verify(signedData, content []byte) ([]*x509.Certificate, error)
```

### `internal/udf`

```go
var ErrAlreadySigned, ErrNotUDF error

// Content returns the bytes that get signed (content.xml).
func Content(udf []byte) ([]byte, error)

// Sign returns a copy of the UDF with sign.sgn added; every other entry is copied unchanged and in order.
func Sign(udf []byte, signContent func(content []byte) ([]byte, error)) ([]byte, error)
```

## HTTP API (127.0.0.1 only)

Default port `47821`. JSON everywhere; errors are `{ "code": "...", "message": "<Turkish>" }`.

| Route | Response |
|---|---|
| `GET /v1/status` | `{ "version": "...", "platformSupported": true }` |
| `GET /v1/certificates` | `CertificateInfo[]` |
| `POST /v1/sign` body `SignRequest` | `SignResponse` (after the native confirmation) |

```ts
type CertificateInfo = {
    id: string              // thumbprint
    subject: string         // common name
    identityNumber: string  // subject serialNumber attribute (TC kimlik no for Turkish qualified certs), '' if absent
    issuer: string          // issuer common name
    notBefore: string       // RFC 3339
    notAfter: string
    keyAlgorithm: 'ECDSA P-256' | 'ECDSA P-384' | 'ECDSA P-521' | 'RSA' | string
    qualified: boolean      // has the qcStatements extension
    valid: boolean          // now within validity and key usage allows digitalSignature or nonRepudiation
}

type SignRequest = {
    certificateId: string
    documents: { id: string; name: string; format: 'udf' | 'cms'; data: string /* base64 */ }[]
}
// 'udf': data is a UDF; the result is the UDF with sign.sgn.
// 'cms': data is arbitrary bytes; the result is a detached CAdES-BES SignedData (DER) over them.

type SignResponse = {
    results: { id: string; data?: string /* base64 */; error?: string }[]
}
```

| Code | Status | When |
|---|---|---|
| `request.invalid_host` | 403 | Host is not `127.0.0.1:<port>` / `localhost:<port>` |
| `request.origin_not_allowed` | 403 | Origin header missing or not in the allowlist (GET without Origin from the demo page is fine) |
| `request.invalid` | 400 | malformed body, `Content-Type` other than `application/json`, unknown format, bad base64, duplicate document id, unsupported key type, too large (limit 50 MB) |
| `request.not_found` | 404 | unknown path |
| `request.method_not_allowed` | 405 | wrong HTTP method for the path |
| `certificate.not_found` | 404 | unknown certificateId |
| `sign.cancelled` | 409 | the user declined the confirmation dialog or the PIN prompt |
| `sign.busy` | 409 | another signing request is in progress |
| `platform.unsupported` | 501 | not running on Windows |
| `internal` | 500 | anything else |

Per-document failures (e.g. an invalid UDF) are reported in `results[i].error`; the batch continues.

### Browser reachability

The page runs on an HTTPS origin and calls `http://127.0.0.1:47821`. `localhost` counts as a secure context, so this is not mixed content. Chrome's Private/Local Network Access may send a preflight with `Access-Control-Request-Private-Network: true`; the connector answers allowed origins with `Access-Control-Allow-Private-Network: true`. Newer Chrome versions may additionally show a one-time "allow access to local network" permission prompt.

### Allowed origins

Baked into the binary at build time (`-ldflags "-X main.allowedOrigins=https://portal.example.com"`), extendable with `--allow-origin` for development. The demo page served by the connector itself (`--demo`) is same-origin.

## Runtime behavior

- Flags: `--port` (default 47821), `--allow-origin <origin>` (repeatable), `--demo` (serve the demo page and open it in the browser), `--idle-timeout` (default 30m, `0` disables; a request in progress, such as an open confirmation window, counts as activity), `--unregister` (remove the URL protocol and exit).
- Single instance: a named mutex; a second launch exits silently, so a web app can start the connector by navigating to `esign-connector://start` without checking first.
- On every start the connector registers `esign-connector://` under `HKCU\Software\Classes` (no admin rights) pointing at its own path.
- Release build: `-ldflags "-H windowsgui -X main.allowedOrigins=https://portal.example.com -X main.version=1.0.0"`. Without `-H windowsgui` a console window stays open, which is handy in development.
- The confirmation window lists the requesting origin, the certificate and up to 15 document names. Names come from the page, so control and invisible direction characters are replaced and long names are cut before they are shown. The default button is "No".
- A cancelled PIN prompt aborts the whole batch with `sign.cancelled`.
