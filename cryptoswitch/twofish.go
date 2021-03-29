package cryptoswitch

import (
	"bytes"
	"fmt"

	"github.com/elizarpif/diploma-elliptic/modes"
	"golang.org/x/crypto/twofish"
)

func encryptTwofish(keyEnc []byte, cipherTextBuf bytes.Buffer, msg []byte) ([]byte, error) {
	block, err := twofish.NewCipher(keyEnc)
	if err != nil {
		return nil, fmt.Errorf("cannot create new TwoFish block: %w", err)
	}

	return modes.EncryptGCM(block, cipherTextBuf, msg)
}

func decryptTwofish(keyEnc []byte, msg []byte) ([]byte, error) {
	block, err := twofish.NewCipher(keyEnc)
	if err != nil {
		return nil, fmt.Errorf("cannot create new TwoFish block: %w", err)
	}

	// TwoFish decryption part
	return modes.DecryptGCM(block, msg)
}
