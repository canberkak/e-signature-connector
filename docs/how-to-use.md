# Using the connector from a web frontend

For the developer (or agent) writing the browser app. The connector is a small Windows program that signs documents with the e-signature (e-imza) token plugged into the user's PC. Your app talks to it over `http://127.0.0.1:47821` with `fetch`. You never see the private key or the PIN; the token driver asks for the PIN in its own window.

Contract details live in [design.md](design.md). This file is the practical guide.

## What happens when the user signs

1. Your page sends the documents and a certificate id to `POST /v1/sign`.
2. The connector opens a **native Windows window** that shows your site's origin, the certificate and the document names, and asks "İmzalamak istiyor musunuz?". The default button is "Hayır".
3. If the user confirms, the token driver may ask for the PIN.
4. The response returns the signed documents.

Your page cannot skip or pre-fill steps 2 and 3. The request stays open while the user answers, so **do not put a short timeout on the sign request** (it can take minutes). Show a "Windows'taki pencereyi onaylayın" state while waiting.

## Setup

- The connector runs only on Windows, and only for origins it was built or started with. An origin is scheme + host + port, exactly as the browser sends it (`https://portal.example.com`, `http://localhost:5173`).
- Development: `esign-connector.exe --allow-origin http://localhost:5173` (repeatable). Add `--demo` to also serve a working test page at `http://127.0.0.1:47821/`; its source (`demo/index.html`) is a complete reference client.
- Production origins are baked into the exe at build time, so tell the connector's owner which origin your app is deployed on.
- Every request must send `Content-Type: application/json` on `POST`. Calls from any other origin fail with 403 `request.origin_not_allowed`.
- Chrome may show a one-time "allow access to local network" prompt the first time your page calls the connector. Tell the user to accept it.

## Detecting and starting the connector

Connection failure (`fetch` throws `TypeError`) means the connector is not running. Starting it:

- The connector registers the URL protocol `esign-connector://` the first time it runs on a PC. Navigating to `esign-connector://start` (for example `window.location.href = "esign-connector://start"`) launches it. The browser may ask the user once for permission.
- Then poll `GET /v1/status` every ~500 ms for ~10 s.
- If it never answers, show the download link for `esign-connector.exe` and explain that it must be run once.
- Starting it again is harmless: a second instance exits silently. The connector quits by itself after 30 minutes without requests.

## API

All responses are JSON. Errors are `{ "code": "...", "message": "<Turkish, safe to show the user>" }`; branch on `code`, show `message`.

### `GET /v1/status`

```json
{ "version": "1.0.0", "platformSupported": true }
```

`platformSupported: false` means the connector is not on Windows; signing will not work.

### `GET /v1/certificates`

Returns the e-signature certificates in the user's Windows certificate store (a plugged-in token shows up here once its driver is installed).

```ts
type CertificateInfo = {
  id: string              // opaque thumbprint, pass it back to /v1/sign
  subject: string         // person's name
  identityNumber: string  // TC kimlik no for Turkish qualified certificates, '' if absent
  issuer: string
  notBefore: string       // RFC 3339
  notAfter: string
  keyAlgorithm: string    // 'ECDSA P-384', 'RSA', ...
  qualified: boolean      // nitelikli elektronik sertifika
  valid: boolean          // within validity and allowed to sign
}
```

- Show certificates with `valid: false` greyed out; do not let the user pick them.
- Prefer `qualified: true` ones. The store can also hold unrelated certificates (Windows' own test or client certificates), so let the user choose, and remember their choice (the thumbprint `id` is stable for a certificate).
- An empty list means the token is not plugged in or its driver is missing.
- Reading the list never asks for a PIN.

### `POST /v1/sign`

```ts
type SignRequest = {
  certificateId: string
  documents: { id: string; name: string; format: 'udf' | 'cms'; data: string /* base64 */ }[]
}
type SignResponse = {
  results: { id: string; data?: string /* base64 */; error?: string }[]
}
```

- `id`: any string unique within the request; results come back with the same ids (and in the same order).
- `name`: shown to the user in the confirmation window. Use the real file name.
- `format: 'udf'`: `data` is a UYAP UDF. The result is the **same UDF with `sign.sgn` added**; save it with the same name.
- `format: 'cms'`: `data` is any bytes. The result is a detached CAdES-BES signature (DER). Save it as `<name>.p7s`; it is not the document itself.
- Send everything the user signs in **one request**: one confirmation window, and the PIN is asked once per batch for most tokens.
- Request body limit is 50 MB in total (base64 is 4/3 of the file size). Split bigger batches into several requests.
- The batch never half-fails silently: a document that cannot be signed has `error` instead of `data` (for example an invalid or already signed UDF) and the others still succeed. Always check each result.

### Error codes you should handle

| `code` | Meaning | What to do |
|---|---|---|
| `sign.cancelled` (409) | The user said no, or cancelled the PIN prompt. Nothing was signed. | Quietly return to the previous state; not an error toast. |
| `sign.busy` (409) | Another signing request is open. | Say that another signing is in progress; do not auto-retry. |
| `certificate.not_found` (404) | The certificate is gone (token unplugged). | Reload `/v1/certificates` and ask the user to choose again. |
| `request.origin_not_allowed` (403) | Your origin is not allowed. | Developer problem; see Setup. |
| `request.invalid` (400) | Bad request (bad base64, unknown format, unsupported key, too large). | Show `message`. |
| `platform.unsupported` (501) | Not Windows. | Show `message`. |
| `internal` (500) | Unexpected. | Show `message`. |

## Minimal client

```ts
const BASE = 'http://127.0.0.1:47821'

class ConnectorError extends Error {
  constructor(public code: string, message: string) { super(message) }
}

async function call<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(BASE + path, init)
  const body = await res.json()
  if (!res.ok) throw new ConnectorError(body.code, body.message)
  return body
}

export const connector = {
  status: () => call<{ version: string; platformSupported: boolean }>('/v1/status'),
  certificates: () => call<CertificateInfo[]>('/v1/certificates'),
  sign: (req: SignRequest) =>
    call<SignResponse>('/v1/sign', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(req),
    }),
}

export async function fileToBase64(file: Blob): Promise<string> {
  const bytes = new Uint8Array(await file.arrayBuffer())
  let binary = ''
  for (let i = 0; i < bytes.length; i += 0x8000) {
    binary += String.fromCharCode(...bytes.subarray(i, i + 0x8000))
  }
  return btoa(binary)
}

export function base64ToBlob(b64: string): Blob {
  const binary = atob(b64)
  const bytes = Uint8Array.from(binary, (c) => c.charCodeAt(0))
  return new Blob([bytes])
}
```

A `fetch` that throws a `TypeError` (no response) means the connector is not running or the browser blocked local network access; handle it separately from `ConnectorError`.

## UX checklist

- On the signing screen: check `status()`; if unreachable, offer "Bileşeni başlat" (protocol link + polling) and the download link.
- Let the user pick the certificate once and show who they are signing as (`subject`, `identityNumber`).
- While `sign()` is pending, disable the button and say that the confirmation window opened on their PC (it can be behind other windows; it is topmost, but say so anyway).
- Treat `sign.cancelled` as the user's choice, not a failure.
- After a result, show per-document success or the document's own `error` text.
- Never log or persist the signed bytes in places the user does not expect; they are legal documents.

## Limits and known gaps

- Windows only; the token's driver must be installed and the certificate visible in Windows' "Kişisel" certificate store.
- The signature format follows a real UYAP UDF (CAdES-BES, detached, no timestamp). It has been verified mathematically and with OpenSSL. **UYAP's own acceptance of a signature produced by this connector has not been tested yet**, so the first real upload should be tried with a throwaway document.
- The connector only signs. Sending a signed document to UYAP is the frontend's (or backend's) business.

## Changing the connector

You are free to change this repository's code whenever the integration needs it: new routes, fields, error codes, different dialog texts, other flags, a different signature profile. You do not need to ask first. If something in the connector gets in your way, fix it here instead of working around it in the frontend.

- Layout: `cmd/connector` (flags, startup), `internal/server` (HTTP API and the confirmation text), `internal/cades` and `internal/udf` (signature format), `internal/certstore` (Windows certificate store + CNG), `internal/winui` (native dialogs, protocol registration), `demo/` (test page).
- Keep the contract in sync: when a route, field or error code changes, update [design.md](design.md) and this file in the same change. `internal/server/messages.go` holds every Turkish text the user can see.
- Code, comments, logs and test names are English; only user-facing texts are Turkish.
- Run before you call it done, from the repo root: `gofmt -l .`, `go vet ./...`, `go test ./...`, `golangci-lint run ./...`. Windows-only parts (`certstore`) also have an integration test: `ESIGN_INTEGRATION=1 go test ./internal/certstore` (it creates and removes its own test certificates).
- Build a test exe with `go build -o bin/esign-connector.exe ./cmd/connector` and start it with `--allow-origin <your dev origin>`.
- Things worth keeping because they are what makes signing safe: the PIN never passes through our code, signing always goes through the native confirmation window, and only allowed origins can call the API. Change them only on purpose.

## Trying it without writing code

```
esign-connector.exe --demo
```

opens the built-in test page: pick a certificate, pick files (`.udf` is signed as UDF, anything else as CMS), sign, download the results.
