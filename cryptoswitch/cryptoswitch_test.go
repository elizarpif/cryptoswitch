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
		alg Cipher
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
				alg: AES,
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
				alg: Twofish,
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
				alg: Twofish,
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
				alg: AES,
				mode: GCM,
			},
			args: args{
				pubkey: privKey.PublicKey,
				msg:    []byte(testingMessage),
			},
			wantErr: false,
		},
		{
			name: "CBC GCM",
			fields: fields{
				alg: AES,
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