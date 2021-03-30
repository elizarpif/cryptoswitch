package cryptoswitch

import (
	"crypto/elliptic"
	"crypto/rand"
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

func (cw *CryptoSwitch) keySize() (size int) {
	switch cw.alg {
	case AES, Camellia, Twofish:
		size = 16
	case DES:
		size = 8
	}

	return
}
