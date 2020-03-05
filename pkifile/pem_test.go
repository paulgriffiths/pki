package pkifile_test

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"errors"
	"reflect"
	"testing"

	"github.com/paulgriffiths/pki/pkifile"
)

func TestPEMBlockFromFile(t *testing.T) {
	t.Parallel()

	var testcases = []struct {
		name     string
		filename string
		pemType  string
		err      error
	}{
		{
			name:     "RSAPrivateKey",
			pemType:  "RSA PRIVATE KEY",
			filename: "testdata/rsa_private_pkcs1.pem",
		},
		{
			name:     "RSAPublicKey/PKCS8",
			pemType:  "PUBLIC KEY",
			filename: "testdata/rsa_public_pkix.pem",
		},
		{
			name:     "ECPrivateKey",
			pemType:  "EC PRIVATE KEY",
			filename: "testdata/ec_private_sec1.pem",
		},
		{
			name:     "ECPublicKey",
			pemType:  "PUBLIC KEY",
			filename: "testdata/ec_public_pkix.pem",
		},
		{
			name:     "TrailingData",
			filename: "testdata/trailing_data.pem",
			err:      pkifile.ErrTrailingData,
		},
		{
			name:     "NotAPEMFile",
			filename: "testdata/not_a_pem.file",
			err:      pkifile.ErrNonPEMData,
		},
		{
			name:     "NoSuchFile",
			filename: "testdata/no_such_file.pem",
			err:      errors.New("no such file"),
		},
	}

	for _, tc := range testcases {
		var tc = tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			block, err := pkifile.PEMBlockFromFile(tc.filename)
			if (err == nil) != (tc.err == nil) {
				t.Fatalf("got error %v, want %v", err, tc.err)
			}

			if block == nil {
				if tc.pemType != "" {
					t.Errorf("expected PEM type %q", tc.pemType)
				}
			} else {
				if block.Type != tc.pemType {
					t.Errorf("got PEM type %q, want %q", block.Type, tc.pemType)
				}
			}
		})
	}
}

func TestPEMBlocksFromFile(t *testing.T) {
	t.Parallel()

	var testcases = []struct {
		name     string
		filename string
		length   int
		err      error
	}{
		{
			name:     "OneBlock",
			filename: "testdata/one_block.pem",
			length:   1,
		},
		{
			name:     "TwoBlocks",
			filename: "testdata/two_blocks.pem",
			length:   2,
		},
		{
			name:     "ThreeBlocks",
			filename: "testdata/three_blocks.pem",
			length:   3,
		},
		{
			name:     "EmptyFile",
			filename: "testdata/empty.file",
			length:   0,
			err:      errors.New("empty file"),
		},
		{
			name:     "TrailingData",
			filename: "testdata/trailing_data.pem",
			length:   0,
			err:      pkifile.ErrTrailingData,
		},
		{
			name:     "NotAPEMFile",
			filename: "testdata/not_a_pem.file",
			length:   0,
			err:      pkifile.ErrNonPEMData,
		},
		{
			name:     "NoSuchFile",
			filename: "testdata/no_such_file.pem",
			length:   0,
			err:      errors.New("no such file"),
		},
	}

	for _, tc := range testcases {
		var tc = tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			blocks, err := pkifile.PEMBlocksFromFile(tc.filename)
			if (err == nil) != (tc.err == nil) {
				t.Fatalf("got error %v, want %v", err, tc.err)
			}

			if len(blocks) != tc.length {
				t.Errorf("got %d blocks, want %d", len(blocks), tc.length)
			}
		})
	}
}

func TestPrivateKeyFromPEMFile(t *testing.T) {
	t.Parallel()

	var testcases = []struct {
		filename string
		keyType  reflect.Type
		err      error
	}{
		{
			filename: "testdata/rsa_private_pkcs1.pem",
			keyType:  reflect.TypeOf((*rsa.PrivateKey)(nil)),
		},
		{
			filename: "testdata/rsa_private_pkcs8.pem",
			keyType:  reflect.TypeOf((*rsa.PrivateKey)(nil)),
		},
		{
			filename: "testdata/ec_private_sec1.pem",
			keyType:  reflect.TypeOf((*ecdsa.PrivateKey)(nil)),
		},
		{
			filename: "testdata/ec_private_pkcs8.pem",
			keyType:  reflect.TypeOf((*ecdsa.PrivateKey)(nil)),
		},
		{
			filename: "testdata/no_such_file.pem",
			err:      errors.New("no such file"),
		},
	}

	for _, tc := range testcases {
		var tc = tc

		t.Run(tc.filename, func(t *testing.T) {
			t.Parallel()

			key, err := pkifile.PrivateKeyFromPEMFile(tc.filename)
			if (err == nil) != (tc.err == nil) {
				t.Fatalf("got error %v, want %v", err, tc.err)
			}

			if keyType := reflect.TypeOf(key); !reflect.DeepEqual(keyType, tc.keyType) {
				t.Errorf("got key type %v, want %v", keyType, tc.keyType)
			}
		})
	}
}

func TestPublicKeyFromPEMFile(t *testing.T) {
	t.Parallel()

	var testcases = []struct {
		filename string
		keyType  reflect.Type
		err      error
	}{
		{
			filename: "testdata/rsa_public_pkix.pem",
			keyType:  reflect.TypeOf((*rsa.PublicKey)(nil)),
		},
		{
			filename: "testdata/rsa_public_pkcs1.pem",
			keyType:  reflect.TypeOf((*rsa.PublicKey)(nil)),
		},
		{
			filename: "testdata/ec_public_pkix.pem",
			keyType:  reflect.TypeOf((*ecdsa.PublicKey)(nil)),
		},
		{
			filename: "testdata/no_such_file.pem",
			err:      errors.New("no such file"),
		},
	}

	for _, tc := range testcases {
		var tc = tc

		t.Run(tc.filename, func(t *testing.T) {
			t.Parallel()

			key, err := pkifile.PublicKeyFromPEMFile(tc.filename)
			if (err == nil) != (tc.err == nil) {
				t.Fatalf("got error %v, want %v", err, tc.err)
			}

			if keyType := reflect.TypeOf(key); !reflect.DeepEqual(keyType, tc.keyType) {
				t.Errorf("got key type %v, want %v", keyType, tc.keyType)
			}
		})
	}
}
