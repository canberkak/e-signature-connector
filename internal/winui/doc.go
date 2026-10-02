// Package winui provides native Windows message boxes, HKCU URL protocol
// registration and the single-instance mutex. On other platforms the dialogs do
// nothing (Confirm reports false) and the registry functions return errors.ErrUnsupported.
package winui
