package winui

import (
	"errors"
	"fmt"
	"strings"
	"sync"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

const (
	idYes           = 6
	maxMessageRunes = 3000
)

// Confirm shows a topmost Yes/No dialog whose default button is No, and reports whether the user chose Yes.
// Any failure to show the dialog returns false.
func Confirm(title, message string) bool {
	ret, err := messageBox(title, message,
		windows.MB_YESNO|windows.MB_ICONQUESTION|windows.MB_TOPMOST|windows.MB_SETFOREGROUND|windows.MB_DEFBUTTON2)
	return err == nil && ret == idYes
}

// ShowError shows a native OK dialog with an error icon.
func ShowError(title, message string) {
	_, _ = messageBox(title, message,
		windows.MB_OK|windows.MB_ICONERROR|windows.MB_TOPMOST|windows.MB_SETFOREGROUND)
}

func messageBox(title, message string, flags uint32) (int32, error) {
	caption, err := windows.UTF16PtrFromString(sanitize(title))
	if err != nil {
		return 0, err
	}
	text, err := windows.UTF16PtrFromString(sanitize(truncate(message)))
	if err != nil {
		return 0, err
	}
	return windows.MessageBox(0, text, caption, flags)
}

// sanitize replaces NULs: UTF16PtrFromString rejects them, and a NUL would end the text early anyway.
func sanitize(s string) string {
	return strings.ReplaceAll(s, "\x00", " ")
}

func truncate(s string) string {
	runes := []rune(s)
	if len(runes) <= maxMessageRunes {
		return s
	}
	return string(runes[:maxMessageRunes]) + "…"
}

// RegisterProtocol registers HKCU\Software\Classes\<scheme> as a URL protocol that runs `"<exePath>" "%1"`.
// It needs no admin rights.
func RegisterProtocol(scheme, exePath string) error {
	if err := checkScheme(scheme); err != nil {
		return err
	}
	if exePath == "" || strings.ContainsAny(exePath, "\"\x00") {
		return errors.New("winui: invalid executable path")
	}

	root, _, err := registry.CreateKey(registry.CURRENT_USER, protocolKey(scheme), registry.SET_VALUE)
	if err != nil {
		return fmt.Errorf("winui: create protocol key: %w", err)
	}
	defer func() { _ = root.Close() }()
	if err := root.SetStringValue("", "URL:"+scheme+" Protocol"); err != nil {
		return fmt.Errorf("winui: set protocol description: %w", err)
	}
	if err := root.SetStringValue("URL Protocol", ""); err != nil {
		return fmt.Errorf("winui: set URL Protocol: %w", err)
	}

	cmd, _, err := registry.CreateKey(registry.CURRENT_USER, protocolKey(scheme)+`\shell\open\command`, registry.SET_VALUE)
	if err != nil {
		return fmt.Errorf("winui: create command key: %w", err)
	}
	defer func() { _ = cmd.Close() }()
	if err := cmd.SetStringValue("", `"`+exePath+`" "%1"`); err != nil {
		return fmt.Errorf("winui: set command: %w", err)
	}
	return nil
}

// UnregisterProtocol removes the protocol key tree; a missing key is not an error.
func UnregisterProtocol(scheme string) error {
	if err := checkScheme(scheme); err != nil {
		return err
	}
	err := deleteTree(protocolKey(scheme))
	if err != nil && !errors.Is(err, registry.ErrNotExist) {
		return fmt.Errorf("winui: delete protocol key: %w", err)
	}
	return nil
}

func protocolKey(scheme string) string {
	return `Software\Classes\` + scheme
}

// An empty or separator-containing scheme would make UnregisterProtocol delete Software\Classes itself or a nested key.
func checkScheme(scheme string) error {
	if scheme == "" || strings.ContainsAny(scheme, `\/`+"\x00") {
		return errors.New("winui: invalid protocol scheme")
	}
	return nil
}

func deleteTree(path string) error {
	k, err := registry.OpenKey(registry.CURRENT_USER, path, registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		return err
	}
	names, err := k.ReadSubKeyNames(-1)
	_ = k.Close()
	if err != nil {
		return err
	}
	for _, name := range names {
		if err := deleteTree(path + `\` + name); err != nil && !errors.Is(err, registry.ErrNotExist) {
			return err
		}
	}
	return registry.DeleteKey(registry.CURRENT_USER, path)
}

// AcquireSingleInstance takes the named mutex Local\<name>. already is true when another holder exists;
// release must be called on exit when already is false. release is safe to call more than once.
func AcquireSingleInstance(name string) (release func(), already bool, err error) {
	if name == "" {
		return nil, false, errors.New("winui: empty mutex name")
	}
	ptr, err := windows.UTF16PtrFromString(`Local\` + name)
	if err != nil {
		return nil, false, err
	}
	// CreateMutex returns a valid handle together with ERROR_ALREADY_EXISTS when the mutex exists.
	h, err := windows.CreateMutex(nil, false, ptr)
	switch {
	case errors.Is(err, windows.ERROR_ALREADY_EXISTS):
		_ = windows.CloseHandle(h)
		return func() {}, true, nil
	case err != nil:
		return nil, false, fmt.Errorf("winui: create mutex: %w", err)
	}
	return sync.OnceFunc(func() { _ = windows.CloseHandle(h) }), false, nil
}
