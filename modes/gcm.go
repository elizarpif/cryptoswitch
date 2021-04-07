package modes

import (
	"bytes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"

	crypterrors "github.com/elizarpif/cryptoswitch/errors"
)

func EncryptGCM(block cipher.Block, cipherTextBuf *bytes.Buffer, msg *[]byte) ([]byte, error) {
	nonceSize := block.BlockSize()

	nonce := make([]byte, nonceSize) //  = длине блока, AES-128
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("cannot read random bytes for nonce: %w", err)
	}

	// добавляем к буферу (инкапсулированный публич ключ + nonce)
	cipherTextBuf.Write(nonce)

	//  режим счетчика Галуа
	aesgcm, err := cipher.NewGCMWithNonceSize(block, nonceSize)
	if err != nil {
		return nil, fmt.Errorf("cannot create aes gcm: %w", err)
	}

	if msg == nil {
		return nil, crypterrors.ErrNilMsg
	}

	ciphertext := aesgcm.Seal(nil, nonce, *msg, nil)
	return ciphertext, nil
}

func DecryptGCM(block cipher.Block, nonce []byte, ciphertext *[]byte) (*[]byte, error) {
	gcm, err := cipher.NewGCMWithNonceSize(block, len(nonce))
	if err != nil {
		return nil, fmt.Errorf("cannot create gcm cipher: %w", err)
	}

	if ciphertext == nil {
		return nil, crypterrors.ErrNilMsg
	}

	plaintext, err := gcm.Open(nil, nonce, *ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("cannot decrypt ciphertext: %w", err)
	}

	return &plaintext, nil
}
