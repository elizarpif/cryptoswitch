package cryptoswitch

import (
	"crypto/hmac"
	"crypto/sha256"
	"hash"
)

func getTag(keyMac, ciphertext []byte) hash.Hash {
	tag := hmac.New(
		sha256.New,
		keyMac,
	)

	// вычисляем тег
	tag.Write(ciphertext)
	return tag
}

func tag(keyMac, ciphertext []byte) []byte {
	tag := getTag(keyMac, ciphertext)

	return tag.Sum(nil)
}

func validTag(tagFromMsg, keyMac, ciphertext []byte) bool {
	tag := getTag(keyMac, ciphertext)

	return hmac.Equal(tag.Sum(nil), tagFromMsg)
}
