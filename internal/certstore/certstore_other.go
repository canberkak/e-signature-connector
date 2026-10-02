//go:build !windows

package certstore

import "errors"

// List is only available on Windows.
func List() ([]Certificate, error) {
	return nil, errors.ErrUnsupported
}

// Open is only available on Windows.
func Open(string) (Signer, error) {
	return nil, errors.ErrUnsupported
}
