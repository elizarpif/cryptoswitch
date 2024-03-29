package cryptoswitch

import (
	"crypto/sha256"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

// Key Derivation Function (KDF) — функция для генерации общих ключей из некоторого набора данных и параметров.
func kdf(secret []byte, size int) (keyEnc, keyMac []byte, err error) {
	keyEnc = make([]byte, size)
	keyMac = make([]byte, size)

	kdf := hkdf.New(sha256.New, secret, nil, nil)
	if _, err := io.ReadFull(kdf, keyEnc); err != nil {
		return nil, nil, fmt.Errorf("cannot read secret from HKDF reader: %w", err)
	}
	if _, err := io.ReadFull(kdf, keyMac); err != nil {
		return nil, nil, fmt.Errorf("cannot read secret from HKDF reader: %w", err)
	}

	return keyEnc, keyMac, nil
}

// zaroPadding добавляет в массив байтов нужное количество нулей
func zeroPadding(b []byte, length int) []byte {
	for i := 0; i < length-len(b); i++ {
		b = append([]byte{0x00}, b...)
	}

	return b
}
