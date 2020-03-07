package extensions

import "errors"

var (
	// ErrTrailingBytes indicates that trailing bytes were found after the
	// extension value.
	ErrTrailingBytes = errors.New("trailing ASN.1 bytes")
)
