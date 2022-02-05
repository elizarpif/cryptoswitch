## Library for ensurance data safety based on elliptic curves
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

#### Camellia
Camellia is a symmetric block encryption algorithm (block size 128 bits, key 128, 192, 256 bits), one of the finalists of the European NESSIE competition. It is a further development of one of the algorithms that participated in the AES competition.[17]
The structure of the algorithm is based on the classical Feistel chain with preliminary and final whitening. The cyclic function uses a nonlinear S-block transformation, a linear scattering block every 16 cycles, a byte-by-byte XOR operation, and a byte permutation.

Depending on the length of the key, it has 18 cycles of a 128-bit key, or 24 cycles of a 192 and 256-bit key. In the software implementation, Camellia was chosen with a block size of 128 bits and a key length equal to 128 bits.

#### Twofish
Twofish is a symmetric block encryption algorithm with a block size of 128 bits and a key length of up to 256 bits. The number of rounds is 16. Developed by a team of specialists led by Bruce Schneier. He was one of the five finalists of the second stage of the AES competition. The algorithm is based on Blowfish, Safer and Square algorithms. [28]

The distinctive features of the algorithm are the use of precomputed and key-dependent s-boxes and a complex scheme for scanning the encryption keys. Half of the n-bit encryption key is used as the encryption key, the other half (on which the s-boxes depend) is used to modify the algorithm.

Twofish was developed specifically taking into account the requirements and recommendations for AES:

● 128-bit block symmetric cipher

● Key lengths of 128, 192 and 256 bits

● No weak keys

● Efficient software and hardware implementation

● Flexibility (the ability to use additional key lengths, use in stream encryption, hash functions, etc.)

● Simplicity of the algorithm

In comparison with Rijndael, it loses in the relative complexity of the algorithm and the speed of execution on most platforms.

The Twofish algorithm is implemented as a mixed Feistel network with four branches that modify each other using Hadamard cryptographic transformation.

The Twofish algorithm is not patented and can be used by anyone without any fees or deductions. It is used in many encryption programs, although it is less widespread than Blowfish.
### Possible encryption modes::
- CBC
- GCM (works only with 128-bit key encryption)

GCM – **Galois/Counter Mode** - counter mode with Galois authentication: this is an authenticated encryption mode, which, in addition, supports the authentication of additional data (transmitted in plain text). In the English literature, this is called AEAD - Authenticated Encryption with Associated Data. In GOST cryptography, this mode is just not enough. Authenticated encryption allows you to detect changes in a message before it is decrypted, for this purpose the message is provided with a special authentication code (in the Russian-speaking tradition, it is also called an imitavka). GCM allows you to protect with an authentication code not only the encrypted part of the message, but also arbitrary attached data – this is useful because, for example, the recipient's address or other open information can be recorded in this data, which, at the same time, needs to be protected from distortion/substitution.