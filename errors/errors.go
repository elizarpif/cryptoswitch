package errors

import (
	"errors"
)

type EncryptionError struct {}

var ErrInvalidTag = errors.New("cryptoswitch: invalid tag")

var ErrNilMsg = errors.New("cryptoswitch: nil message")