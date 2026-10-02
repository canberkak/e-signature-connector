//go:build windows

package winui

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"unicode/utf8"

	"golang.org/x/sys/windows/registry"
)

func uniqueName(t *testing.T) string {
	t.Helper()
	b := make([]byte, 6)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return "esign-test-" + hex.EncodeToString(b)
}

func readString(t *testing.T, path, name string) string {
	t.Helper()
	k, err := registry.OpenKey(registry.CURRENT_USER, path, registry.QUERY_VALUE)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer func() { _ = k.Close() }()
	v, _, err := k.GetStringValue(name)
	if err != nil {
		t.Fatalf("read %s %q: %v", path, name, err)
	}
	return v
}

func TestRegisterAndUnregisterProtocol(t *testing.T) {
	scheme := uniqueName(t)
	t.Cleanup(func() { _ = UnregisterProtocol(scheme) })

	exe := `C:\Program Files\esign\esign-connector.exe`
	if err := RegisterProtocol(scheme, exe); err != nil {
		t.Fatal(err)
	}

	key := `Software\Classes\` + scheme
	if got := readString(t, key, ""); got != "URL:"+scheme+" Protocol" {
		t.Errorf("description = %q", got)
	}
	if got := readString(t, key, "URL Protocol"); got != "" {
		t.Errorf("URL Protocol = %q, want empty", got)
	}
	want := `"` + exe + `" "%1"`
	if got := readString(t, key+`\shell\open\command`, ""); got != want {
		t.Errorf("command = %q, want %q", got, want)
	}

	if err := RegisterProtocol(scheme, exe); err != nil {
		t.Errorf("second RegisterProtocol: %v", err)
	}

	if err := UnregisterProtocol(scheme); err != nil {
		t.Fatal(err)
	}
	if _, err := registry.OpenKey(registry.CURRENT_USER, key, registry.QUERY_VALUE); !errors.Is(err, registry.ErrNotExist) {
		t.Errorf("key still present after unregister: %v", err)
	}
	if err := UnregisterProtocol(scheme); err != nil {
		t.Errorf("UnregisterProtocol of a missing key: %v", err)
	}
}

func TestProtocolRejectsBadInput(t *testing.T) {
	for _, scheme := range []string{"", `a\b`, "a/b"} {
		if err := RegisterProtocol(scheme, `C:\x.exe`); err == nil {
			t.Errorf("RegisterProtocol(%q) succeeded", scheme)
		}
		if err := UnregisterProtocol(scheme); err == nil {
			t.Errorf("UnregisterProtocol(%q) succeeded", scheme)
		}
	}
	if err := RegisterProtocol(uniqueName(t), ""); err == nil {
		t.Error("RegisterProtocol with empty exe path succeeded")
	}
}

func TestAcquireSingleInstance(t *testing.T) {
	name := uniqueName(t)

	release, already, err := AcquireSingleInstance(name)
	if err != nil {
		t.Fatal(err)
	}
	if already {
		t.Fatal("first acquire reported already")
	}

	release2, already, err := AcquireSingleInstance(name)
	if err != nil {
		t.Fatal(err)
	}
	if !already {
		t.Error("second acquire did not report already")
	}
	release2()

	release()
	release() // idempotent

	release3, already, err := AcquireSingleInstance(name)
	if err != nil {
		t.Fatal(err)
	}
	defer release3()
	if already {
		t.Error("acquire after release reported already")
	}
}

func TestTruncate(t *testing.T) {
	short := strings.Repeat("ş", maxMessageRunes)
	if got := truncate(short); got != short {
		t.Error("message at the limit was changed")
	}
	got := truncate(short + "x")
	if n := utf8.RuneCountInString(got); n != maxMessageRunes+1 || !strings.HasSuffix(got, "…") {
		t.Errorf("truncated to %d runes, suffix ok = %v", n, strings.HasSuffix(got, "…"))
	}
}

func TestSanitize(t *testing.T) {
	if got := sanitize("a\x00b"); got != "a b" {
		t.Errorf("sanitize = %q", got)
	}
}
