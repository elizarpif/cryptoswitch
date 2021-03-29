package cryptoswitch

import (
	"bytes"
	"crypto/aes"
	"errors"
	"fmt"

	"github.com/elizarpif/diploma-elliptic/modes"
)

func (cw *CryptoSwitch) encryptAES(sharedSecret, keyMac []byte, cipherTextBuf bytes.Buffer, msg []byte) ([]byte, error) {
	block, err := aes.NewCipher(sharedSecret)
	if err != nil {
		return nil, fmt.Errorf("cannot create new AES block: %w", err)
	}

	switch cw.mode {
	case GCM:
		return modes.EncryptGCM(block, keyMac, cipherTextBuf, msg)
	case CBC:
		return modes.EncryptCBC(block, keyMac, cipherTextBuf, msg)
	}

	return nil, errors.New("unknown mode")
}

func (cw *CryptoSwitch) decryptAES(ss, keyMac []byte, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(ss)
	if err != nil {
		return nil, fmt.Errorf("cannot create new AES block: %w", err)
	}

	// AES decryption part
	switch cw.mode {
	case GCM:
		return modes.DecryptGCM(block, keyMac, ciphertext)
	case CBC:
		return modes.DecryptCBC(block, keyMac, ciphertext)
	}

	return nil, errors.New("unknown mode")
}
