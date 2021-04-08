package cryptoswitch

import (
	"crypto/hmac"
	"crypto/sha256"
	"hash"
)

func getTag(keyMac []byte, ciphertext *[]byte) hash.Hash {
	tag := hmac.New(
		sha256.New,
		keyMac,
	)

	// вычисляем тег
	tag.Write(*ciphertext)
	return tag
}

func tag(keyMac []byte, ciphertext *[]byte) []byte {
	tag := getTag(keyMac, ciphertext)

	return tag.Sum(nil)
}

func validTag(tagFromMsg, keyMac []byte, ciphertext *[]byte) bool {
	tag := getTag(keyMac, ciphertext)

	return hmac.Equal(tag.Sum(nil), tagFromMsg)
}
