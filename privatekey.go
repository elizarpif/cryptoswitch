package cryptoswitch

import (
	"bytes"
	"crypto/elliptic"
	"math/big"
)

type PrivateKey struct {
	*PublicKey
	D *big.Int
}

// PublicKey instance with nested elliptic.Curve interface (secp256k1 instance in our case)
type PublicKey struct {
	elliptic.Curve
	X, Y *big.Int
}

// Bytes returns public key raw bytes;
// Could be optionally compressed by dropping Y part
func (k *PublicKey) Bytes() []byte {
	x := k.X.Bytes()
	if len(x) < 32 {
		for i := 0; i < 32-len(x); i++ {
			x = append([]byte{0}, x...)
		}
	}

	//if compressed {
	//	// If odd
	//	if k.Y.Bit(0) != 0 {
	//		return bytes.Join([][]byte{{0x03}, x}, nil)
	//	}
	//
	//	// If even
	//	return bytes.Join([][]byte{{0x02}, x}, nil)
	//}

	y := k.Y.Bytes()
	if len(y) < 32 {
		for i := 0; i < 32-len(y); i++ {
			y = append([]byte{0}, y...)
		}
	}

	return bytes.Join([][]byte{{0x04}, x, y}, nil)
}
