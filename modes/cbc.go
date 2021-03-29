package modes

import (
	"bytes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"io"
)

func blockModeEncrypt(c BlockMode, data []byte) ([]byte, error) {
	// дополняем последний блок
	src, dst := Padding(data, c.BlockSize())

	err := c.CryptBlocks(dst, src)
	if err != nil {
		return nil, err
	}

	return dst, nil
}

func blockModeDecrypt(c BlockMode, data []byte) ([]byte, error) {
	src := data
	dst := make([]byte, len(data))

	err := c.CryptBlocks(dst, src)
	if err != nil {
		return nil, err
	}

	// избавляемся от набивки
	res := Unpadding(dst)

	return res, nil
}

func encryptCBC(block cipher.Block, data []byte) ([]byte, error) {
	// The IV needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the ciphertext.
	iv := make([]byte, block.BlockSize())
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	mode, err := NewCBCEncrypter(block, iv)
	if err != nil {
		return nil, err
	}

	ret, err := blockModeEncrypt(mode, data)
	if err != nil {
		return nil, err
	}

	// добавляем вектор инициализации (длина = 16)
	ret = append(iv, ret...)

	return ret, nil
}

func decryptCBC(block cipher.Block, ciphertext []byte) ([]byte, error) {
	iv := ciphertext[:block.BlockSize()]
	ciphertext = ciphertext[block.BlockSize():]

	decrypter, err := NewCBCDecrypter(block, iv)
	if err != nil {
		return nil, err
	}

	return blockModeDecrypt(decrypter, ciphertext)
}

func EncryptCBC(block cipher.Block, keyMac []byte, cipherTextBuf bytes.Buffer, msg []byte) ([]byte, error) {
	ciphertext, err := encryptCBC(block, msg)
	if err != nil {
		return nil, err
	}

	tag := tag(keyMac, ciphertext)

	cipherTextBuf.Write(ciphertext)
	cipherTextBuf.Write(tag)

	return cipherTextBuf.Bytes(), nil
}

func DecryptCBC(block cipher.Block, keyMac, msg []byte) ([]byte, error) {
	tagFromMsg := msg[len(msg)-32:]
	ciphertext := msg[:len(msg)-32]

	if !validTag(tagFromMsg, keyMac, ciphertext) {
		return nil, errors.New("invalid tag")
	}

	return decryptCBC(block, ciphertext)
}
