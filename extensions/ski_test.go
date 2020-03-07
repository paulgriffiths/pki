package extensions_test

import (
	"bytes"
	"crypto/x509/pkix"
	"errors"
	"reflect"
	"testing"

	"encoding/asn1"

	pgasn1 "github.com/paulgriffiths/pki/asn1"
	"github.com/paulgriffiths/pki/extensions"
	"github.com/paulgriffiths/pki/pkifile"
)

func TestSubjectKeyIdentifierMarshal(t *testing.T) {
	t.Parallel()

	var testcases = []struct {
		name string
		ext  extensions.SubjectKeyIdentifier
		want pkix.Extension
		err  error
	}{
		{
			name: "OK",
			ext: extensions.SubjectKeyIdentifier{
				Critical: true,
				ID:       []byte{1, 2, 3, 4},
			},
			want: pkix.Extension{
				Id:       pgasn1.OIDSubjectKeyIdentifier,
				Critical: true,
				Value:    []byte{asn1.TagOctetString, 4, 1, 2, 3, 4},
			},
		},
		{
			name: "Empty",
			ext: extensions.SubjectKeyIdentifier{
				Critical: true,
			},
			want: pkix.Extension{},
			err:  errors.New("no ID"),
		},
	}

	for _, tc := range testcases {
		var tc = tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := tc.ext.Marshal()
			if (err == nil) != (tc.err == nil) {
				t.Fatalf("got error %v, want %v", err, tc.err)
			}

			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
}

func TestSubjectKeyIdentifierUnmarshal(t *testing.T) {
	t.Parallel()

	var testcases = []struct {
		name string
		ext  pkix.Extension
		want extensions.SubjectKeyIdentifier
		err  error
	}{
		{
			name: "OK",
			ext: pkix.Extension{
				Id:       pgasn1.OIDSubjectKeyIdentifier,
				Critical: true,
				Value:    []byte{asn1.TagOctetString, 4, 1, 2, 3, 4},
			},
			want: extensions.SubjectKeyIdentifier{
				Critical: true,
				ID:       []byte{1, 2, 3, 4},
			},
		},
		{
			name: "BadOID",
			ext: pkix.Extension{
				Id:       pgasn1.OIDAuthorityKeyIdentifier,
				Critical: false,
				Value:    []byte{asn1.TagOctetString | bit6, 4, 1, 2, 3, 4},
			},
			want: extensions.SubjectKeyIdentifier{},
			err:  errors.New("bad OID"),
		},
	}

	for _, tc := range testcases {
		var tc = tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var got extensions.SubjectKeyIdentifier

			err := got.Unmarshal(tc.ext)
			if (err == nil) != (tc.err == nil) {
				t.Fatalf("got error %v, want %v", err, tc.err)
			}

			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
}

func TestMakePublicKeyIdentifierUnmarshal(t *testing.T) {
	t.Parallel()

	var testcases = []struct {
		filename string
		want     []byte
		err      error
	}{
		{
			filename: "testdata/rsa_public.pem",
			want: []byte{139, 122, 233, 0, 202, 196, 176, 136, 23, 29,
				139, 141, 212, 216, 106, 85, 40, 88, 245, 184},
		},
	}

	for _, tc := range testcases {
		var tc = tc

		t.Run(tc.filename, func(t *testing.T) {
			t.Parallel()

			key, err := pkifile.PublicKeyFromPEMFile(tc.filename)
			if err != nil {
				t.Fatalf("couldn't read public key: %v", err)
			}

			got, err := extensions.MakePublicKeyIdentifier(key)
			if (err == nil) != (tc.err == nil) {
				t.Fatalf("got error %v, want %v", err, tc.err)
			}

			if !bytes.Equal(got, tc.want) {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
}
