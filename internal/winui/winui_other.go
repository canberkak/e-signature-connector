//go:build !windows

package winui

import "errors"

func Confirm(string, string) bool { return false }

func ShowError(string, string) {}

func RegisterProtocol(string, string) error { return errors.ErrUnsupported }

func UnregisterProtocol(string) error { return errors.ErrUnsupported }

func AcquireSingleInstance(string) (release func(), already bool, err error) {
	return func() {}, false, nil
}
