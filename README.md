## Library for the ensurance data safety based on elliptic curves
Package cryptoswitch realizes scheme ECIES with choice of encryption algorythm (symmetric encryption algorithms such as AES, TwoFish, etc., and encryption mode are supplied to the input)

### ECIES

![Encryption](https://github.com/elizarpif/diploma-elliptic/blob/develop/assets/ecies_encryption.png)

![Decryption](https://github.com/elizarpif/diploma-elliptic/blob/develop/assets/ecies_decryption.png)

### Available algorythms:
- **AES**
- **DES**
- **Twofish**
- **Camellia**

```go
privKey, err := cryptoswitch.GenerateKey()
if err != nil {
    log.WithError(err).Error("can't generate private key")
    return err
}

cw := cryptoswitch.NewCryptoSwitch(cryptoswitch.AES, cryptoswitch.GCM)

encrypt, err := cw.Encrypt(privKey.PublicKey, []byte(testingMessage))
if err != nil {
    log.WithError(err).Error("can't encrypt aes")
    return err
}
```
### Ciphers

#### AES
The AES algorithm (also known as the Rijndael algorithm) is a symmetrical block cipher algorithm that takes plain text in blocks of 128 bits and converts them to ciphertext using keys of 128, 192, and 256 bits. Since the AES algorithm is considered secure, it is in the worldwide standard.

#### DES
DES stands for Data Encryption Standard. There are certain machines that can be used to crack the DES algorithm. The DES algorithm uses a key of 56-bit size. Using this key, the DES takes a block of 64-bit plain text as input and generates a block of 64-bit cipher text.

The DES process has several steps involved in it, where each step is called a round. Depending upon the size of the key being used, the number of rounds varies. For example, a 128-bit key requires 10 rounds, a 192-bit key requires 12 rounds, and so on.

#### Camellia
Camellia is a symmetric block encryption algorithm (block size 128 bits, key 128, 192, 256 bits), one of the finalists of the European NESSIE competition. It is a further development of one of the algorithms that participated in the AES competition.
The structure of the algorithm is based on the classical Feistel chain with preliminary and final whitening. The cyclic function uses a nonlinear S-block transformation, a linear scattering block every 16 cycles, a byte-by-byte XOR operation, and a byte permutation.

Depending on the length of the key, it has 18 cycles of a 128-bit key, or 24 cycles of a 192 and 256-bit key. In the software implementation, Camellia was chosen with a block size of 128 bits and a key length equal to 128 bits.

#### Twofish
Twofish is a symmetric block encryption algorithm with a block size of 128 bits and a key length of up to 256 bits. The number of rounds is 16. Developed by a team of specialists led by Bruce Schneier. He was one of the five finalists of the second stage of the AES competition. The algorithm is based on Blowfish, Safer and Square algorithms.


### Possible encryption modes:
- CBC
- GCM (works only with 128-bit key encryption)

#### CBC
The Cipher Block Chaining (CBC) mode is a typical block cipher mode of operation using block cipher algorithm. How CBC mode works? For the encryption of the initial block, an IV is generated. This IV should be an unpredictable, unique value that is openly transmitted to the recipient.  It is not a secret.

This IV is XORed with the plaintext before passing it to the encryption algorithm.  The resulting ciphertext is then used to carry information to the encryption of the next block and so on.

This relationship between blocks helps to protect against identical plaintext blocks producing identical ciphertext blocks.  Since each block of the plaintext is XORed with a different IV before encryption, it produces a unique ciphertext.  This means that an attacker observing the string of ciphertexts can’t learn anything from the fact that two ciphertext blocks are identical.

A major advantage of CBC mode is that, while encryption must be performed sequentially, decryption can be parallelized.  The first IV is a public value and all other blocks use a ciphertext as an IV, which are public.  This can make decryption faster than other block cipher modes of operation.

#### GCM

GCM – **Galois/Counter Mode** - counter mode with Galois authentication: this is an authenticated encryption mode, which, in addition, supports the authentication of additional data (transmitted in plain text). In the English literature, this is called AEAD - Authenticated Encryption with Associated Data. In GOST cryptography, this mode is just not enough. Authenticated encryption allows you to detect changes in a message before it is decrypted, for this purpose the message is provided with a special authentication code (in the Russian-speaking tradition, it is also called an imitavka). GCM allows you to protect with an authentication code not only the encrypted part of the message, but also arbitrary attached data – this is useful because, for example, the recipient's address or other open information can be recorded in this data, which, at the same time, needs to be protected from distortion/substitution.
