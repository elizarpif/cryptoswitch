package main

import (
	"diploma-elliptic/cryptoswitch"
	"errors"

	"github.com/elizarpif/logger"
)

func main() {
	log := logger.NewLogger()
	err := testEncrypt(log)

	if err != nil {
		log.Fatal(err)
	}
}

const testingMessage = "this is a test"

func testEncrypt(log logger.Logger) error {
	privKey, err := cryptoswitch.GenerateKey()
	if err != nil {
		log.WithError(err).Error("can't generate private key")
		return err
	}

	cw := cryptoswitch.NewCryptoSwitch(cryptoswitch.Aes)

	encrypt, err := cw.Encrypt(privKey.PublicKey, []byte(testingMessage))
	if err != nil {
		log.WithError(err).Error("can't encrypt aes")
		return err
	}

	decrypt, err := cw.Decrypt(privKey, encrypt)
	if err != nil {
		log.WithError(err).Error("can't decrypt aes")
		return err
	}

	if testingMessage != string(decrypt) {
		log.Error("message not equal decrypted")
		return errors.New("invalid decrypt message")
	}

	return nil
}
