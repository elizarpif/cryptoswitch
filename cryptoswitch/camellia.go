package cryptoswitch

import (
	"bytes"
	"fmt"

	"github.com/elizarpif/camellia"
	"github.com/elizarpif/diploma-elliptic/modes"
)

func encryptCamellia(sharedSecret, keyMac []byte, cipherTextBuf bytes.Buffer, msg []byte) ([]byte, error) {
	block, err := camellia.NewCipher(sharedSecret)
	if err != nil {
		return nil, fmt.Errorf("cannot create new Camellia block: %w", err)
	}

	return modes.EncryptGCM(block, keyMac, cipherTextBuf, msg)
}

func decryptCamellia(ss, keyMac, msg []byte) ([]byte, error) {
	// Camellia decryption part
	block, err := camellia.NewCipher(ss)
	if err != nil {
		return nil, fmt.Errorf("cannot create new Camellia block: %w", err)
	}

	// AES decryption part
	return modes.DecryptGCM(block, keyMac, msg)
}
