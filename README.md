## Библиотека обеспечения безопасности данных на основе эллиптических кривых

Пакет cryptoswitch реализует схему ECIES с выбором алгоритма шифрования (на вход подаются симметричные алгоритмы шифрования, такие как AES, DES, 3DES и т.д. )

Возможные алгоритмы:
- AES
- DES
- 3DES (TripleDES)
- RC5
- Blowfish
- Twofish
- RC4
- SEAl

```go
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
```