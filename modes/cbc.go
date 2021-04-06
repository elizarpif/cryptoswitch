package modes

import (
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"io"
)

func blockModeEncrypt(c BlockMode, data *[]byte) (*[]byte, error) {
	// дополняем последний блок
	src, dst := Padding(data, c.BlockSize())

	err := c.CryptBlocks(dst, src)
	if err != nil {
		return nil, err
	}

	return &dst, nil
}

func blockModeDecrypt(c BlockMode, data *[]byte) (*[]byte, error) {
	if data == nil {
		return nil, errors.New("data = nil")
	}
	src := *data
	dst := make([]byte, len(src))

	err := c.CryptBlocks(dst, src)
	if err != nil {
		return nil, err
	}

	// избавляемся от набивки
	res := Unpadding(dst)

	return &res, nil
}

func encryptCBC(block cipher.Block, data *[]byte) (*[]byte, error) {
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
	res := append(iv, (*ret)...)

	return &res, nil
}

func decryptCBC(block cipher.Block, ciphertextPtr *[]byte) (*[]byte, error) {
	if ciphertextPtr == nil{
		return nil, errors.New("ciphertext = nil")
	}
	ciphertext := *ciphertextPtr

	iv := ciphertext[:block.BlockSize()]
	ciphertext = ciphertext[block.BlockSize():]

	decrypter, err := NewCBCDecrypter(block, iv)
	if err != nil {
		return nil, err
	}

	return blockModeDecrypt(decrypter, &ciphertext)
}

func EncryptCBC(block cipher.Block, msg *[]byte) (*[]byte, error) {
	return encryptCBC(block, msg)
}

func DecryptCBC(block cipher.Block, msg *[]byte) (*[]byte, error) {
	return decryptCBC(block, msg)
}
