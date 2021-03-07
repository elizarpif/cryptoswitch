package cryptoswitch

import (
	"bytes"
	"crypto/aes"
	"diploma-elliptic/modes"
	"errors"
	"fmt"
)

func (cw *CryptoSwitch) encryptAES(sharedSecret, keyMac  []byte, cipherTextBuf bytes.Buffer, msg []byte) ([]byte, error) {
	block, err := aes.NewCipher(sharedSecret)
	if err != nil {
		return nil, fmt.Errorf("cannot create new AES block: %w", err)
	}

	switch cw.mode {
	case GCM:
		return modes.EncryptGCM(block, cipherTextBuf, msg)
	case CBC:
		return modes.EncryptCBC(block,keyMac, cipherTextBuf, msg)
	}

	return nil, errors.New("unknown mode")
}

func blockModeEncrypt(c modes.BlockMode, data []byte) ([]byte, error) {
	// дополняем последний блок
	src, dst := modes.Padding(data, c.BlockSize())

	err := c.CryptBlocks(dst, src)
	if err != nil {
		return nil, err
	}

	return dst, nil
}

func blockModeDecrypt(c modes.BlockMode, data []byte) ([]byte, error) {
	src := data
	dst := make([]byte, len(data))

	err := c.CryptBlocks(dst, src)
	if err != nil {
		return nil, err
	}

	// избавляемся от набивки
	res := modes.Unpadding(dst)

	return res, nil
}

func (cw *CryptoSwitch) decryptAES(ss, keyMac []byte, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(ss)
	if err != nil {
		return nil, fmt.Errorf("cannot create new AES block: %w", err)
	}

	// AES decryption part
	switch cw.mode {
	case GCM:
		return modes.DecryptGCM(block, ciphertext)
	case CBC:
		return modes.DecryptCBC(block, keyMac, ciphertext)
	}

	return nil, errors.New("unknown mode")
}
