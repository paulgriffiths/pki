package extensions_test

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"reflect"
	"testing"

	"encoding/asn1"

	pgasn1 "github.com/paulgriffiths/pki/asn1"
	"github.com/paulgriffiths/pki/extensions"
)

func TestKeyUsageMarshal(t *testing.T) {
	t.Parallel()

	var testcases = []struct {
		name string
		ext  extensions.KeyUsage
		want pkix.Extension
		err  error
	}{
		{
			name: "Empty",
			ext:  extensions.KeyUsage{},
			want: pkix.Extension{},
			err:  errors.New("no key usages specified"),
		},
		{
			name: "All",
			ext: extensions.KeyUsage{
				Critical: false,
				Value: x509.KeyUsageDigitalSignature |
					x509.KeyUsageContentCommitment |
					x509.KeyUsageKeyEncipherment |
					x509.KeyUsageDataEncipherment |
					x509.KeyUsageKeyAgreement |
					x509.KeyUsageCertSign |
					x509.KeyUsageCRLSign |
					x509.KeyUsageEncipherOnly |
					x509.KeyUsageDecipherOnly,
			},
			want: pkix.Extension{
				Id:       pgasn1.OIDKeyUsage,
				Critical: false,
				Value:    []byte{asn1.TagBitString, 3, 7, 0xff, 0x80},
			},
		},
		{
			name: "CA",
			ext: extensions.KeyUsage{
				Critical: true,
				Value: x509.KeyUsageCertSign |
					x509.KeyUsageCRLSign,
			},
			want: pkix.Extension{
				Id:       pgasn1.OIDKeyUsage,
				Critical: true,
				Value:    []byte{asn1.TagBitString, 3, 7, 0x06, 0},
			},
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

func TestKeyUsageUnmarshal(t *testing.T) {
	t.Parallel()

	var testcases = []struct {
		name string
		ext  pkix.Extension
		want extensions.KeyUsage
		err  error
	}{
		{
			name: "Empty",
			ext: pkix.Extension{
				Id:       pgasn1.OIDKeyUsage,
				Critical: false,
				Value:    []byte{asn1.TagBitString, 3, 7, 0, 0},
			},
			want: extensions.KeyUsage{},
		},
		{
			name: "All",
			ext: pkix.Extension{
				Id:       pgasn1.OIDKeyUsage,
				Critical: false,
				Value:    []byte{asn1.TagBitString, 3, 7, 0xff, 0x80},
			},
			want: extensions.KeyUsage{
				Critical: false,
				Value: x509.KeyUsageDigitalSignature |
					x509.KeyUsageContentCommitment |
					x509.KeyUsageKeyEncipherment |
					x509.KeyUsageDataEncipherment |
					x509.KeyUsageKeyAgreement |
					x509.KeyUsageCertSign |
					x509.KeyUsageCRLSign |
					x509.KeyUsageEncipherOnly |
					x509.KeyUsageDecipherOnly,
			},
		},
		{
			name: "CA",
			ext: pkix.Extension{
				Id:       pgasn1.OIDKeyUsage,
				Critical: true,
				Value:    []byte{asn1.TagBitString, 3, 7, 0x06, 0},
			},
			want: extensions.KeyUsage{
				Critical: true,
				Value: x509.KeyUsageCertSign |
					x509.KeyUsageCRLSign,
			},
		},
		{
			name: "BadOID",
			ext: pkix.Extension{
				Id:       pgasn1.OIDExtendedKeyUsage,
				Critical: true,
				Value:    []byte{asn1.TagBitString, 3, 7, 0x06, 0},
			},
			want: extensions.KeyUsage{},
			err:  errors.New("bad OID"),
		},
		{
			name: "TrailingBytes",
			ext: pkix.Extension{
				Id:       pgasn1.OIDKeyUsage,
				Critical: true,
				Value:    []byte{asn1.TagBitString, 3, 7, 0x06, 0, 0xff},
			},
			want: extensions.KeyUsage{},
			err:  errors.New("trailing bytes"),
		},
		{
			name: "BadASN1",
			ext: pkix.Extension{
				Id:       pgasn1.OIDKeyUsage,
				Critical: true,
				Value:    []byte{0xff},
			},
			want: extensions.KeyUsage{},
			err:  errors.New("bad ASN.1"),
		},
	}

	for _, tc := range testcases {
		var tc = tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var got extensions.KeyUsage

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
