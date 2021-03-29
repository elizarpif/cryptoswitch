package cryptoswitch

import (
	"bytes"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"

	"github.com/fomichev/secp256k1"
)

type Cipher int

const (
	AES Cipher = iota
	DES
	TripleDES
	RC5
	Blowfish
	Twofish
	Camellia
	RC4
	SEAL
)

type Mode int

const (
	CBC Mode = iota
	GCM
)

type CryptoSwitch struct {
	alg  Cipher
	mode Mode
}

func NewCryptoSwitch(cipher Cipher, mode Mode) *CryptoSwitch {
	return &CryptoSwitch{alg: cipher, mode: mode}
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
func (cw *CryptoSwitch) Encrypt(bobPubKey *PublicKey, msg []byte) ([]byte, error) {
	var cipherTextBuf bytes.Buffer

	// Generate ephemeral key
	aliceKeyPair, err := GenerateKey()
	if err != nil {
		return nil, err
	}

	cipherTextBuf.Write(aliceKeyPair.PublicKey.Bytes())

	// Derive shared secret
	keyEnc, keyMac, err := aliceKeyPair.Encapsulate(bobPubKey)
	if err != nil {
		return nil, err
	}

	switch cw.alg {
	case AES:
		// AES encryption
		return cw.encryptAES(keyEnc, keyMac, cipherTextBuf, msg)
	case DES:
		return encryptDES(keyEnc, cipherTextBuf, msg)
	case Twofish:
		return encryptTwofish(keyEnc, cipherTextBuf, msg)
	case Camellia:
		return encryptCamellia(keyEnc, cipherTextBuf, msg)
	default:
		return nil, errors.New("unknown cipher type")
	}
}

// Decrypt decrypts a passed message with a receiver private key, returns plaintext or decryption error
func (cw *CryptoSwitch) Decrypt(bobPrivKey *PrivateKey, msg []byte) ([]byte, error) {
	// Message cannot be less than length of public key (65) + nonce (16) + tag (16)
	if cw.mode == GCM && len(msg) <= (1+32+32+16+16) {
		return nil, fmt.Errorf("invalid length of message")
	}

	// Ephemeral sender public key
	alicePubkey := &PublicKey{
		Curve: secp256k1.SECP256K1(),
		X:     new(big.Int).SetBytes(msg[1:33]),
		Y:     new(big.Int).SetBytes(msg[33:65]),
	}

	// Shift message
	msg = msg[65:]

	// Derive shared secret
	keyEnc, keyMac, err := alicePubkey.Decapsulate(bobPrivKey)
	if err != nil {
		return nil, err
	}

	switch cw.alg {
	case AES:
		// AES encryption
		return cw.decryptAES(keyEnc, keyMac, msg)
	case DES:
		return decryptDES(keyEnc, msg)
	case Twofish:
		return decryptTwofish(keyEnc, msg)
	case Camellia:
		return decryptCamellia(keyEnc, msg)
	default:
		return nil, errors.New("unknown cipher type")
	}
}
