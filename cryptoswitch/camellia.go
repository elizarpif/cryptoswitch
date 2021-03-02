package cryptoswitch

import (
	"bytes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"

	"github.com/elizarpif/camellia"
)

func encryptCamellia(sharedSecret []byte, cipherTextBuf bytes.Buffer, msg []byte) ([]byte, error) {
	block, err := camellia.NewCipher(sharedSecret)
	if err != nil {
		return nil, fmt.Errorf("cannot create new camellia block: %w", err)
	}

	nonce := make([]byte, 16) // вектор инициализации? = длине блока, AES-128
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("cannot read random bytes for nonce: %w", err)
	}

	// добавляем к буферу (эфемерный публич ключ + IV)
	cipherTextBuf.Write(nonce)

	//  режим счетчика Галуа
	aesgcm, err := cipher.NewGCMWithNonceSize(block, 16)
	if err != nil {
		return nil, fmt.Errorf("cannot create camellia gcm: %w", err)
	}

	ciphertext := aesgcm.Seal(nil, nonce, msg, nil)

	tag := ciphertext[len(ciphertext)-aesgcm.NonceSize():]
	cipherTextBuf.Write(tag)
	ciphertext = ciphertext[:len(ciphertext)-len(tag)]
	cipherTextBuf.Write(ciphertext)

	return cipherTextBuf.Bytes(), nil
}

func decryptCamellia(ss []byte, msg []byte) ([]byte, error) {
	// Camellia decryption part
	nonce := msg[:16]
	tag := msg[16:32]

	// Create Golang-accepted ciphertext
	ciphertext := bytes.Join([][]byte{msg[32:], tag}, nil)

	block, err := camellia.NewCipher(ss)
	if err != nil {
		return nil, fmt.Errorf("cannot create new camellia block: %w", err)
	}

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
