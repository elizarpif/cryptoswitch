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

// Encapsulate инакпсулирует ключ используя KEM (Key Encapsulation Mechanism)
func (ephemeralKey *PrivateKey) Encapsulate(pub *PublicKey) ([]byte, []byte, error) {
	if pub == nil {
		return nil, nil, fmt.Errorf("public key is empty")
	}

	var secret bytes.Buffer
	secret.Write(ephemeralKey.PublicKey.Bytes()) // эфемерный публичный ключ

	sx, sy := pub.Curve.ScalarMult(pub.X, pub.Y, ephemeralKey.D.Bytes())
	secret.Write([]byte{0x04}) // end of transmission

	// Иногда shared secret coordinates меньше 32 байтов, дозаполняем
	l := len(pub.Curve.Params().P.Bytes()) // порядок поля
	secret.Write(zeroPadding(sx.Bytes(), l))
	secret.Write(zeroPadding(sy.Bytes(), l))

	return kdf(secret.Bytes())
}
