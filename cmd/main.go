package main

import (
	"fmt"
	"log"
	"math/big"

	"github.com/ecies/go"
	"github.com/xiphon/ellipticbinary"
)

func main() {
	curve := &ellipticbinary.Curve{}
	// GF(2^4)
	curve.P = big.NewInt(16)
	curve.N = big.NewInt(20)
	curve.Gx = big.NewInt(4)  /// 0100
	curve.Gy = big.NewInt(10) // 1010
	curve.A, _ = new(big.Int).SetString("0", 10)
	curve.B, _ = new(big.Int).SetString("1", 10)
	curve.BitSize = 16

	//curve.IsOnCurve(big.NewInt(2),big.NewInt(2))

	priv, err := eciesgo.GenerateKey()
	if err != nil{
		log.Fatal(err)
	}

	encrypt, err := eciesgo.Encrypt(priv.PublicKey, []byte("привет! как дела? алле ааааааааааааааааааа   ииииии"))
	if err != nil{
		log.Fatal(err)
	}

	fmt.Println(string(encrypt))

	decrypt, err := eciesgo.Decrypt(priv, encrypt)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(string(decrypt))
}
