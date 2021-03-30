package cryptoswitch

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"errors"
	"fmt"
	"math/big"

	"github.com/elizarpif/camellia"
	"github.com/elizarpif/cryptoswitch/modes"
	"github.com/fomichev/secp256k1"

	"golang.org/x/crypto/twofish"
)

// Decapsulate decapsulates key by using Key Encapsulation Mechanism and returns k_enc, k_mac
func (cw *CryptoSwitch) Decapsulate(alicePubKey *PublicKey, bobPrivKy *PrivateKey) ([]byte, []byte, error) {
	if bobPrivKy == nil {
		return nil, nil, fmt.Errorf("public key is empty")
	}

	var secret bytes.Buffer
	secret.Write(alicePubKey.Bytes())

	sx, sy := bobPrivKy.Curve.ScalarMult(alicePubKey.X, alicePubKey.Y, bobPrivKy.D.Bytes())
	secret.Write([]byte{0x04})

	// Sometimes shared secret coordinates are less than 32 bytes; Big Endian
	l := len(bobPrivKy.Curve.Params().P.Bytes())
	secret.Write(zeroPadding(sx.Bytes(), l))
	secret.Write(zeroPadding(sy.Bytes(), l))

	var size = cw.keySize()

	return kdf(secret.Bytes(), size)
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
	keyEnc, keyMac, err := cw.Decapsulate(alicePubkey, bobPrivKey)
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

	return cw.decrypt(block, keyMac, msg)
}

func (cw *CryptoSwitch) decrypt(block cipher.Block, keyMac []byte, msg []byte) ([]byte, error) {
	switch cw.mode {
	case GCM:
		nonceSize := block.BlockSize()

		nonce := msg[:nonceSize]
		tag := msg[len(msg)-32:]

		ciphertext := msg[nonceSize : len(msg)-32]

		if !validTag(tag, keyMac, ciphertext) {
			return nil, errors.New("invalid tag")
		}

		return modes.DecryptGCM(block, nonce, ciphertext)
	case CBC:
		tagFromMsg := msg[len(msg)-32:]
		ciphertext := msg[:len(msg)-32]

		if !validTag(tagFromMsg, keyMac, ciphertext) {
			return nil, errors.New("invalid tag")
		}

		return modes.DecryptCBC(block, keyMac, ciphertext)
	}

	return nil, errors.New("unknown mode")
}
