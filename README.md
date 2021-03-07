## Библиотека обеспечения безопасности данных на основе эллиптических кривых

Пакет cryptoswitch реализует схему ECIES с выбором алгоритма шифрования (на вход подаются симметричные алгоритмы шифрования, такие как AES, DES, 3DES и т.д. )

Возможные алгоритмы:
- **AES**
- DES
- 3DES (TripleDES)
- RC5
- Blowfish
- **Twofish**
- **Camellia**
- RC4
- SEAl

```go
privKey, err := cryptoswitch.GenerateKey()
if err != nil {
    log.WithError(err).Error("can't generate private key")
    return err
}

cw := cryptoswitch.NewCryptoSwitch(cryptoswitch.AES)

encrypt, err := cw.Encrypt(privKey.PublicKey, []byte(testingMessage))
if err != nil {
    log.WithError(err).Error("can't encrypt aes")
    return err
}
```

### Режимы шифрования:
- CBC
- GCM
#### Шифрование AES, TwoFish, Camellia осуществляется с использованием режима GCM

GCM – **Galois/Counter Mode** – режим счётчика с аутентификацией Галуа: это режим аутентифицированного шифрования, который, к тому же, поддерживает аутентификацию дополнительных данных (передаются в открытом виде). В англоязычной литературе это называется AEAD – Authenticated Encryption with Associated Data. В ГОСТовой криптографии такого режима как раз не хватает. Аутентифицированное шифрование позволяет обнаружить изменения сообщения до его расшифрования, для этого сообщение снабжается специальным кодом аутентификации (в русскоязычной традиции также называется имитовставкой). GCM позволяет защитить кодом аутентификации не только шифрованную часть сообщения, но и произвольные прикреплённые данные – это полезно, потому что в этих данных может быть записан, например, адрес получателя или другая открытая информация, которую, вместе с тем, требуется защитить от искажений/подмены.