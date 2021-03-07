package cryptoswitch

import (
	"bytes"
	"fmt"
	"math/big"
)

type PrivateKey struct {
	*PublicKey
	D *big.Int
}

// Encapsulate encapsulates key by using Key Encapsulation Mechanism and returns symmetric key;
// can be safely used as encryption key
func (k *PrivateKey) Encapsulate(pub *PublicKey) ([]byte, []byte, error) {
	if pub == nil {
		return nil, nil, fmt.Errorf("public key is empty")
	}

	var secret bytes.Buffer
	secret.Write(k.PublicKey.Bytes())

	sx, sy := pub.Curve.ScalarMult(pub.X, pub.Y, k.D.Bytes())
	secret.Write([]byte{0x04})

	// Sometimes shared secret coordinates are less than 32 bytes; Big Endian
	l := len(pub.Curve.Params().P.Bytes())
	secret.Write(zeroPad(sx.Bytes(), l))
	secret.Write(zeroPad(sy.Bytes(), l))

	return kdf(secret.Bytes())
}
