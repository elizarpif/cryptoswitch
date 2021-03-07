package cryptoswitch

import (
	"crypto/sha256"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

// Key Derivation Function (KDF) — функция для генерации общих ключей из некоторого набора данных и параметров.
func kdf(secret []byte) (keyEnc, keyMac []byte, err error) {
	keyEnc = make([]byte, 32)
	keyMac = make([]byte, 32)

	kdf := hkdf.New(sha256.New, secret, nil, nil)
	if _, err := io.ReadFull(kdf, keyEnc); err != nil {
		return nil,nil, fmt.Errorf("cannot read secret from HKDF reader: %w", err)
	}
	if _, err := io.ReadFull(kdf, keyMac); err != nil {
		return nil,nil, fmt.Errorf("cannot read secret from HKDF reader: %w", err)
	}

	return keyEnc, keyMac, nil
}

func zeroPad(b []byte, leigth int) []byte {
	for i := 0; i < leigth-len(b); i++ {
		b = append([]byte{0x00}, b...)
	}

	return b
}
