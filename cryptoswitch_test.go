package cryptoswitch

import (
	"fmt"
	"io/ioutil"
	"testing"
	"time"
)

const testingMessage = "this is a test"

func TestCryptoSwitch_Encrypt(t *testing.T) {
	privKey, err := GenerateKey()
	if err != nil {
		t.Fatalf("can't generate private key: %v", err)
	}

	type fields struct {
		alg  Cipher
		mode Mode
	}
	type args struct {
		pubkey *PublicKey
		msg    []byte
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    []byte
		wantErr bool
	}{
		{
			name: "AES",
			fields: fields{
				alg:  AES,
				mode: CBC,
			},
			args: args{
				pubkey: privKey.PublicKey,
				msg:    []byte(testingMessage),
			},
			wantErr: false,
		},
		{
			name: "Twofish",
			fields: fields{
				alg:  Twofish,
				mode: CBC,
			},
			args: args{
				pubkey: privKey.PublicKey,
				msg:    []byte(testingMessage),
			},
			wantErr: false,
		},
		{
			name: "Camellia",
			fields: fields{
				alg:  Twofish,
				mode: CBC,
			},
			args: args{
				pubkey: privKey.PublicKey,
				msg:    []byte(testingMessage),
			},
			wantErr: false,
		},
		{
			name: "DES",
			fields: fields{
				alg:  DES,
				mode: CBC,
			},
			args: args{
				pubkey: privKey.PublicKey,
				msg:    []byte(testingMessage),
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cw := &CryptoSwitch{
				alg: tt.fields.alg,
			}
			got, err := cw.Encrypt(tt.args.pubkey, tt.args.msg)
			if (err != nil) != tt.wantErr {
				t.Errorf("Encrypt() error = %v", err)
				return
			}

			decrypt, err := cw.Decrypt(privKey, got)
			if err != nil || (string(decrypt) != testingMessage) {
				t.Errorf("Decrypt() got = %v, want %v", string(decrypt), testingMessage)
			}
		})
	}
}

func TestCryptoSwitch_Encrypt_Mode(t *testing.T) {
	privKey, err := GenerateKey()
	if err != nil {
		t.Fatalf("can't generate private key: %v", err)
	}

	type fields struct {
		alg  Cipher
		mode Mode
	}
	type args struct {
		pubkey *PublicKey
		msg    []byte
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    []byte
		wantErr bool
	}{
		{
			name: "AES GCM",
			fields: fields{
				alg:  AES,
				mode: GCM,
			},
			args: args{
				pubkey: privKey.PublicKey,
				msg:    []byte(testingMessage),
			},
			wantErr: false,
		},
		{
			name: "AES CBC",
			fields: fields{
				alg:  AES,
				mode: CBC,
			},
			args: args{
				pubkey: privKey.PublicKey,
				msg:    []byte(testingMessage),
			},
			wantErr: false,
		},
		{
			name: "DES GCM - не работает для этого режима(ибо нужен 128битный ключ)",
			fields: fields{
				alg:  DES,
				mode: GCM,
			},
			args: args{
				pubkey: privKey.PublicKey,
				msg:    []byte(testingMessage),
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cw := &CryptoSwitch{
				alg:  tt.fields.alg,
				mode: tt.fields.mode,
			}
			got, err := cw.Encrypt(tt.args.pubkey, tt.args.msg)
			if (err != nil) != tt.wantErr {
				t.Errorf("Encrypt() error = %v", err)
				return
			}
			if !tt.wantErr {
				decrypt, err := cw.Decrypt(privKey, got)
				if err != nil || (string(decrypt) != testingMessage) {
					t.Errorf("Decrypt() got = %v, want %v", string(decrypt), testingMessage)
				}
			}
		})
	}
}

const fileName = "testdata/goblet.avi"

func openfile(filename string) ([]byte, error) {
	dat, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	return dat, nil
}

func BenchmarkCryptoSwitch_Encrypt_AES_File(b *testing.B) {
	privKey, err := GenerateKey()
	if err != nil {
		b.Fatalf("can't generate private key: %v", err)
	}

	bytes2, err2 := openfile("testdata/2.mp4")
	if err2 != nil {
		b.Fatal(err2)
	}

	type fields struct {
		alg  Cipher
		mode Mode
	}
	type args struct {
		pubkey *PublicKey
		msg    []byte
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    []byte
		wantErr bool
	}{
		{
			name: "AES GCM",
			fields: fields{
				alg:  AES,
				mode: GCM,
			},
			args: args{
				pubkey: privKey.PublicKey,
				msg:    bytes2,
			},
			wantErr: false,
		},
		//{
		//	name: "AES CBC",
		//	fields: fields{
		//		alg:  AES,
		//		mode: CBC,
		//	},
		//	args: args{
		//		pubkey: privKey.PublicKey,
		//		msg:    bytes2,
		//	},
		//	wantErr: false,
		//},
		//{
		//	name: "Camellia GCM",
		//	fields: fields{
		//		alg:  Camellia,
		//		mode: GCM,
		//	},
		//	args: args{
		//		pubkey: privKey.PublicKey,
		//		msg:    bytes2,
		//	},
		//	wantErr: false,
		//},
		//{
		//	name: "Camellia CBC",
		//	fields: fields{
		//		alg:  Camellia,
		//		mode: CBC,
		//	},
		//	args: args{
		//		pubkey: privKey.PublicKey,
		//		msg:    bytes2,
		//	},
		//	wantErr: false,
		//},
		{
			name: "Twofish GCM",
			fields: fields{
				alg:  Twofish,
				mode: GCM,
			},
			args: args{
				pubkey: privKey.PublicKey,
				msg:    bytes2,
			},
			wantErr: false,
		},
		//{
		//	name: "Twofish CBC",
		//	fields: fields{
		//		alg:  Twofish,
		//		mode: CBC,
		//	},
		//	args: args{
		//		pubkey: privKey.PublicKey,
		//		msg:    bytes2,
		//	},
		//	wantErr: false,
		//},
		//{
		//	name: "DES CBC",
		//	fields: fields{
		//		alg:  DES,
		//		mode: CBC,
		//	},
		//	args: args{
		//		pubkey: privKey.PublicKey,
		//		msg:    bytes2,
		//	},
		//	wantErr: false,
		//},
	}
	for _, tt := range tests {

		//b.StartTimer()
		b.Run(tt.name, func(b *testing.B) {
			//for i:=0 ; i < b.N; i++ {
			b.ResetTimer()
				cw := &CryptoSwitch{
					alg:  tt.fields.alg,
					mode: tt.fields.mode,
				}

				_, err := cw.Encrypt(tt.args.pubkey, tt.args.msg)
				if (err != nil) != tt.wantErr {
					b.Errorf("Encrypt() error = %v", err)
					return
				}

		//	}
		})
	}
}

func BenchmarkCryptoSwitch_Encrypt_GCM(b *testing.B) {
	privKey, err := GenerateKey()
	if err != nil {
		b.Fatalf("can't generate private key: %v", err)
	}

	cw := &CryptoSwitch{
		alg:  Twofish,
		mode: GCM,
	}

	testFile, err := openfile(fileName)
	if err != nil {
		b.Fatalf("can't generate private key: %v", err)
	}

	b.ResetTimer()
	b.Run("gcm", func(b *testing.B) {
		for i := 0; i < 1; i++ {
			_, err := cw.Encrypt(privKey.PublicKey, []byte(testFile))
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}

func BenchmarkCryptoSwitch_Encrypt_CBC(b *testing.B) {
	privKey, err := GenerateKey()
	if err != nil {
		b.Fatalf("can't generate private key: %v", err)
	}

	cw := &CryptoSwitch{
		alg:  Twofish,
		mode: CBC,
	}

	testFile, err := openfile(fileName)
	if err != nil {
		b.Fatalf("can't generate private key: %v", err)
	}

	b.ResetTimer()
	b.StartTimer()
	t1 := time.Now()
	//b.Run("cbc", func(b *testing.B) {
		//for i := 0; i < b.N; i++ {
			_, err = cw.Encrypt(privKey.PublicKey, testFile)
			if err != nil {
				b.Fatal(err)
			}
		//}
	//})
	t2 :=time.Now()
	res := t2.Sub(t1).Nanoseconds()
	fmt.Print(res)
}
