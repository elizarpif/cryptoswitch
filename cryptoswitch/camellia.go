package cryptoswitch

import (
	"bytes"
	"diploma-elliptic/modes"
	"fmt"

	"github.com/elizarpif/camellia"
)

func encryptCamellia(sharedSecret []byte, cipherTextBuf bytes.Buffer, msg []byte) ([]byte, error) {
	block, err := camellia.NewCipher(sharedSecret)
	if err != nil {
		return nil, fmt.Errorf("cannot create new Camellia block: %w", err)
	}

	return modes.EncryptGCM(block, cipherTextBuf, msg)
}

func decryptCamellia(ss []byte, msg []byte) ([]byte, error) {
	// Camellia decryption part
	block, err := camellia.NewCipher(ss)
	if err != nil {
		return nil, fmt.Errorf("cannot create new Camellia block: %w", err)
	}

	// AES decryption part
	return modes.DecryptGCM(block, msg)
}
