package cryptoswitch

import (
	"testing"
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

			decrypt, err := cw.Decrypt(privKey, got)
			if err != nil || (string(decrypt) != testingMessage) {
				t.Errorf("Decrypt() got = %v, want %v", string(decrypt), testingMessage)
			}
		})
	}
}

func BenchmarkCryptoSwitch_Encrypt_GCM(b *testing.B) {
	privKey, err := GenerateKey()
	if err != nil {
		b.Fatalf("can't generate private key: %v", err)
	}

	cw := &CryptoSwitch{
		alg:  AES,
		mode: GCM,
	}

	b.ResetTimer()
	b.Run("gcm", func(b *testing.B) {
		for i := 0; i < 1000; i++ {
			_, err := cw.Encrypt(privKey.PublicKey, []byte(testingMessage))
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
		alg:  AES,
		mode: CBC,
	}

	b.ResetTimer()
	b.Run("cbc", func(b *testing.B) {
		for i := 0; i < 1000; i++ {
			_, err := cw.Encrypt(privKey.PublicKey, []byte(testingMessage))
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}
