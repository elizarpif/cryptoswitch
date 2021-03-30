package cryptoswitch

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"errors"
	"fmt"

	"github.com/elizarpif/camellia"
	"github.com/elizarpif/diploma-elliptic/modes"

	"golang.org/x/crypto/twofish"
)

// Decapsulate decapsulates key by using Key Encapsulation Mechanism and returns symmetric key;
// can be safely used as encryption key
func (cw *CryptoSwitch) Encapsulate(alicePriveKey *PrivateKey, bobPubKey *PublicKey) ([]byte, []byte, error) {
	if bobPubKey == nil {
		return nil, nil, fmt.Errorf("public key is empty")
	}

	var secret bytes.Buffer
	secret.Write(alicePriveKey.PublicKey.Bytes()) // эфемерный публичный ключ

	sx, sy := bobPubKey.Curve.ScalarMult(bobPubKey.X, bobPubKey.Y, alicePriveKey.D.Bytes())
	secret.Write([]byte{0x04}) // end of transmission

	// Иногда shared secret coordinates меньше 32 байтов, дозаполняем
	l := len(bobPubKey.Curve.Params().P.Bytes()) // порядок поля
	secret.Write(zeroPadding(sx.Bytes(), l))
	secret.Write(zeroPadding(sy.Bytes(), l))

	var size = cw.keySize()

	return kdf(secret.Bytes(), size)
}

// Encrypt encrypts a passed message with a receiver public key, returns ciphertext or encryption error
func (cw *CryptoSwitch) Encrypt(bobPubKey *PublicKey, msg []byte) ([]byte, error) {
	var cipherTextBuf bytes.Buffer

	alicePrivKey, err := GenerateKey()
	if err != nil {
		return nil, err
	}

	cipherTextBuf.Write(alicePrivKey.PublicKey.Bytes())

	keyEnc, keyMac, err := cw.Encapsulate(alicePrivKey, bobPubKey)
	if err != nil {
		return nil, err
	}

	var block cipher.Block

	switch cw.alg {
	case AES:
		block, err = aes.NewCipher(keyEnc)
		if err != nil {
			return nil, errors.New("can't create eas")
		}

	case DES:
		block, err = des.NewCipher(keyEnc)
		if err != nil {
			return nil, errors.New("can't create des")
		}

	case Twofish:
		block, err = twofish.NewCipher(keyEnc)
		if err != nil {
			return nil, errors.New("can't create des")
		}

	case Camellia:
		block, err = camellia.NewCipher(keyEnc)
		if err != nil {
			return nil, errors.New("can't create des")
		}

	default:
		return nil, errors.New("unknown cipher type")
	}

	return cw.encrypt(block, keyMac, cipherTextBuf, msg)
}

func (cw *CryptoSwitch) encrypt(block cipher.Block, keyMac []byte, cipherTextBuf bytes.Buffer, msg []byte) ([]byte, error) {
	switch cw.mode {
	case GCM:
		ciphertext, err := modes.EncryptGCM(block, &cipherTextBuf, msg)
		if err != nil {
			return nil, errors.New("can't encrypt gcm")
		}

		cipherTextBuf.Write(ciphertext)
		cipherTextBuf.Write(tag(keyMac, ciphertext))

		return cipherTextBuf.Bytes(), nil
	case CBC:
		ciphertext, err := modes.EncryptCBC(block, keyMac, cipherTextBuf, msg)
		if err != nil {
			return nil, errors.New("can't encrypt cbc")
		}

		tag := tag(keyMac, ciphertext)

		cipherTextBuf.Write(ciphertext)
		cipherTextBuf.Write(tag)

		return cipherTextBuf.Bytes(), nil
	}

	return nil, errors.New("unknown mode")
}
