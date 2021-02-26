package cryptoswitch

import (
	"bytes"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"math/big"

	"github.com/fomichev/secp256k1"
)

func Algs() {
	//elliptic.CurveParams{}
	//elliptic.Curve()
}

// GenerateKey generates secp256k1 key pair
func GenerateKey() (*PrivateKey, error) {
	curve := secp256k1.SECP256K1()

	p, x, y, err := elliptic.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("cannot generate key pair: %w", err)
	}

	return &PrivateKey{
		PublicKey: &PublicKey{
			Curve: curve,
			X:     x,
			Y:     y,
		},
		D: new(big.Int).SetBytes(p),
	}, nil
}

// Encrypt encrypts a passed message with a receiver public key, returns ciphertext or encryption error
func Encrypt(pubkey *PublicKey, msg []byte) ([]byte, error) {
	var cipherTextBuf bytes.Buffer

	// Generate ephemeral key
	ephemeralKey, err := GenerateKey()
	if err != nil {
		return nil, err
	}

	cipherTextBuf.Write(ephemeralKey.PublicKey.Bytes())

	// Derive shared secret
	sharedSecret, err := ephemeralKey.Encapsulate(pubkey)
	if err != nil {
		return nil, err
	}

	// AES encryption
	return encryptAES(sharedSecret, cipherTextBuf, msg)
}

// Decrypt decrypts a passed message with a receiver private key, returns plaintext or decryption error
func Decrypt(privkey *PrivateKey, msg []byte) ([]byte, error) {
	// Message cannot be less than length of public key (65) + nonce (16) + tag (16)
	if len(msg) <= (1 + 32 + 32 + 16 + 16) {
		return nil, fmt.Errorf("invalid length of message")
	}

	// Ephemeral sender public key
	ethPubkey := &PublicKey{
		Curve: secp256k1.SECP256K1(),
		X:     new(big.Int).SetBytes(msg[1:33]),
		Y:     new(big.Int).SetBytes(msg[33:65]),
	}

	// Shift message
	msg = msg[65:]

	// Derive shared secret
	ss, err := ethPubkey.Decapsulate(privkey)
	if err != nil {
		return nil, err
	}

	return decryptAES(ss, msg)
}
