package modes

import (
	"bytes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
)

func EncryptGCM(block cipher.Block, keyMac []byte, cipherTextBuf bytes.Buffer, msg []byte) ([]byte, error) {
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

	cipherTextBuf.Write(ciphertext)
	cipherTextBuf.Write(tag(keyMac, ciphertext))

	return cipherTextBuf.Bytes(), nil
}

func DecryptGCM(block cipher.Block, keyMac, msg []byte) ([]byte, error) {
	nonce := msg[:16]
	tag := msg[len(msg)-32:]

	ciphertext := msg[16:len(msg)-32]

	if !validTag(tag, keyMac, ciphertext) {
		return nil, errors.New("invalid tag")
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
