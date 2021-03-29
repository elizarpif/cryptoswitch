package modes

import (
	"bytes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
)

func EncryptGCM(block cipher.Block, cipherTextBuf bytes.Buffer, msg []byte) ([]byte, error) {
	nonce := make([]byte, 16) //  = длине блока, AES-128
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("cannot read random bytes for nonce: %w", err)
	}

	// добавляем к буферу (инкапсулированный публич ключ + nonce)
	cipherTextBuf.Write(nonce)

	//  режим счетчика Галуа
	aesgcm, err := cipher.NewGCMWithNonceSize(block, 16)
	if err != nil {
		return nil, fmt.Errorf("cannot create aes gcm: %w", err)
	}

	ciphertext := aesgcm.Seal(nil, nonce, msg, nil)

	tag := ciphertext[len(ciphertext)-aesgcm.NonceSize():]
	cipherTextBuf.Write(tag)
	ciphertext = ciphertext[:len(ciphertext)-len(tag)]
	cipherTextBuf.Write(ciphertext)

	return cipherTextBuf.Bytes(), nil
}

func DecryptGCM(block cipher.Block, msg []byte) ([]byte, error) {
	nonce := msg[:16]
	tag := msg[16:32]

	// Create Golang-accepted ciphertext
	ciphertext := bytes.Join([][]byte{msg[32:], tag}, nil)

	gcm, err := cipher.NewGCMWithNonceSize(block, 16)
	if err != nil {
		return nil, fmt.Errorf("cannot create gcm cipher: %w", err)
	}

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("cannot decrypt ciphertext: %w", err)
	}

	return plaintext, nil
}
