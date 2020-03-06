package extensions_test

import (
	"crypto/x509/pkix"
	"errors"
	"reflect"
	"testing"

	"encoding/asn1"

	pgasn1 "github.com/paulgriffiths/pki/asn1"
	"github.com/paulgriffiths/pki/extensions"
)

func TestExtendedKeyUsageMarshal(t *testing.T) {
	t.Parallel()

	var testcases = []struct {
		name string
		ext  extensions.ExtendedKeyUsage
		want pkix.Extension
		err  error
	}{
		{
			name: "Empty",
			ext:  extensions.ExtendedKeyUsage{},
			want: pkix.Extension{},
			err:  errors.New("no extended key usages specified"),
		},
		{
			name: "TLSServer",
			ext: extensions.ExtendedKeyUsage{
				Critical: false,
				OIDs: []asn1.ObjectIdentifier{
					{1, 3, 6, 1, 5, 5, 7, 3, 1},
				},
			},
			want: pkix.Extension{
				Id:       pgasn1.OIDExtendedKeyUsage,
				Critical: false,
				Value: []byte{asn1.TagSequence | bit6, 10,
					asn1.TagOID, 8, 40*1 + 3, 6, 1, 5, 5, 7, 3, 1},
			},
		},
		{
			name: "TLSServerAndClient",
			ext: extensions.ExtendedKeyUsage{
				Critical: true,
				OIDs: []asn1.ObjectIdentifier{
					{1, 3, 6, 1, 5, 5, 7, 3, 1},
					{1, 3, 6, 1, 5, 5, 7, 3, 2},
				},
			},
			want: pkix.Extension{
				Id:       pgasn1.OIDExtendedKeyUsage,
				Critical: true,
				Value: []byte{asn1.TagSequence | bit6, 20,
					asn1.TagOID, 8, 40*1 + 3, 6, 1, 5, 5, 7, 3, 1,
					asn1.TagOID, 8, 40*1 + 3, 6, 1, 5, 5, 7, 3, 2},
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

func TestExtendedKeyUsageUnmarshal(t *testing.T) {
	t.Parallel()

	var testcases = []struct {
		name string
		ext  pkix.Extension
		want extensions.ExtendedKeyUsage
		err  error
	}{
		{
			name: "Empty",
			ext: pkix.Extension{
				Id:       pgasn1.OIDExtendedKeyUsage,
				Critical: false,
				Value:    []byte{asn1.TagSequence | bit6, 0},
			},
			want: extensions.ExtendedKeyUsage{
				OIDs: []asn1.ObjectIdentifier{},
			},
		},
		{
			name: "TLSServer",
			ext: pkix.Extension{
				Id:       pgasn1.OIDExtendedKeyUsage,
				Critical: false,
				Value: []byte{asn1.TagSequence | bit6, 10,
					asn1.TagOID, 8, 40*1 + 3, 6, 1, 5, 5, 7, 3, 1},
			},
			want: extensions.ExtendedKeyUsage{
				Critical: false,
				OIDs: []asn1.ObjectIdentifier{
					{1, 3, 6, 1, 5, 5, 7, 3, 1},
				},
			},
		},
		{
			name: "TLSServerAndClient",
			ext: pkix.Extension{
				Id:       pgasn1.OIDExtendedKeyUsage,
				Critical: true,
				Value: []byte{asn1.TagSequence | bit6, 20,
					asn1.TagOID, 8, 40*1 + 3, 6, 1, 5, 5, 7, 3, 1,
					asn1.TagOID, 8, 40*1 + 3, 6, 1, 5, 5, 7, 3, 2},
			},
			want: extensions.ExtendedKeyUsage{
				Critical: true,
				OIDs: []asn1.ObjectIdentifier{
					{1, 3, 6, 1, 5, 5, 7, 3, 1},
					{1, 3, 6, 1, 5, 5, 7, 3, 2},
				},
			},
		},
		{
			name: "BadOID",
			ext: pkix.Extension{
				Id:       pgasn1.OIDBasicConstraints,
				Critical: false,
				Value:    []byte{asn1.TagSequence | bit6, 0},
			},
			want: extensions.ExtendedKeyUsage{},
			err:  errors.New("bad OID"),
		},
	}

	for _, tc := range testcases {
		var tc = tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var got extensions.ExtendedKeyUsage

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
