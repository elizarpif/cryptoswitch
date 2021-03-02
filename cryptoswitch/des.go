package cryptoswitch

import (
	"bytes"
	"errors"
)

func encryptDES(ss []byte, ct bytes.Buffer, msg []byte) ([]byte, error) {
	return nil, errors.New("unimplemented des encryption")
}

func decryptDES(ss []byte, msg []byte) ([]byte, error) {
	return nil, errors.New("unimplemented des decryption")
}
