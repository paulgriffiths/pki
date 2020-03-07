package extensions_test

import (
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"reflect"
	"testing"

	"encoding/asn1"

	pgasn1 "github.com/paulgriffiths/pki/asn1"
	"github.com/paulgriffiths/pki/extensions"
)

func TestAuthorityKeyIdentifierMarshal(t *testing.T) {
	t.Parallel()

	var testcases = []struct {
		name string
		ext  extensions.AuthorityKeyIdentifier
		want pkix.Extension
		err  error
	}{
		{
			name: "OK/IDOnly",
			ext: extensions.AuthorityKeyIdentifier{
				Critical: true,
				ID:       []byte{1, 2, 3, 4},
			},
			want: pkix.Extension{
				Id:       pgasn1.OIDAuthorityKeyIdentifier,
				Critical: true,
				Value: []byte{asn1.TagSequence | bit6, 6,
					asn1.ClassContextSpecific<<6 | 0x00, 4, 1, 2, 3, 4,
				},
			},
		},
		{
			name: "OK/IDAndSerialNumber",
			ext: extensions.AuthorityKeyIdentifier{
				Critical:     true,
				ID:           []byte{1, 2, 3, 4},
				SerialNumber: big.NewInt(42),
			},
			want: pkix.Extension{
				Id:       pgasn1.OIDAuthorityKeyIdentifier,
				Critical: true,
				Value: []byte{asn1.TagSequence | bit6, 9,
					asn1.ClassContextSpecific << 6, 4, 1, 2, 3, 4,
					asn1.ClassContextSpecific<<6 | 0x02, 1, 42,
				},
			},
		},
		{
			name: "Empty",
			ext: extensions.AuthorityKeyIdentifier{
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

func TestAuthorityKeyIdentifierUnmarshal(t *testing.T) {
	t.Parallel()

	var testcases = []struct {
		name string
		ext  pkix.Extension
		want extensions.AuthorityKeyIdentifier
		err  error
	}{
		{
			name: "OK",
			ext: pkix.Extension{
				Id:       pgasn1.OIDAuthorityKeyIdentifier,
				Critical: true,
				Value: []byte{asn1.TagSequence | bit6, 9,
					asn1.ClassContextSpecific << 6, 4, 1, 2, 3, 4,
					asn1.ClassContextSpecific<<6 | 0x02, 1, 42,
				},
			},
			want: extensions.AuthorityKeyIdentifier{
				Critical:     true,
				ID:           []byte{1, 2, 3, 4},
				SerialNumber: big.NewInt(42),
			},
		},
		{
			name: "BadOID",
			ext: pkix.Extension{
				Id:       pgasn1.OIDSubjectKeyIdentifier,
				Critical: false,
				Value:    []byte{asn1.TagSequence | bit6, 6, asn1.ClassContextSpecific << 6, 4, 1, 2, 3, 4},
			},
			want: extensions.AuthorityKeyIdentifier{},
			err:  errors.New("bad OID"),
		},
		{
			name: "TrailingBytes",
			ext: pkix.Extension{
				Id:       pgasn1.OIDAuthorityKeyIdentifier,
				Critical: true,
				Value: []byte{asn1.TagSequence | bit6, 6,
					asn1.ClassContextSpecific<<6 | 0x00, 4, 1, 2, 3, 4, 0xff,
				},
			},
			want: extensions.AuthorityKeyIdentifier{},
			err:  errors.New("trailing bytes"),
		},
		{
			name: "BadASN1",
			ext: pkix.Extension{
				Id:       pgasn1.OIDAuthorityKeyIdentifier,
				Critical: true,
				Value:    []byte{0xff},
			},
			want: extensions.AuthorityKeyIdentifier{},
			err:  errors.New("bad ASN.1"),
		},
	}

	for _, tc := range testcases {
		var tc = tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var got extensions.AuthorityKeyIdentifier

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
