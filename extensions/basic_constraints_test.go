package extensions_test

import (
	"crypto/x509/pkix"
	"errors"
	"reflect"
	"testing"

	goasn1 "encoding/asn1"

	"github.com/paulgriffiths/pki/asn1"
	"github.com/paulgriffiths/pki/extensions"
)

const bit6 = 0x01 << 5

func TestBasicConstraintsMarshal(t *testing.T) {
	t.Parallel()

	var testcases = []struct {
		name string
		ext  extensions.BasicConstraints
		want pkix.Extension
	}{
		{
			name: "NotCA",
			ext:  extensions.BasicConstraints{},
			want: pkix.Extension{
				Id:       asn1.OIDBasicConstraints,
				Critical: false,
				Value:    []byte{goasn1.TagSequence | bit6, 3, goasn1.TagBoolean, 1, 0x0},
			},
		},
		{
			name: "CA/NoMaxPathLen",
			ext:  extensions.BasicConstraints{Critical: true, IsCA: true, MaxPathLen: -1},
			want: pkix.Extension{
				Id:       asn1.OIDBasicConstraints,
				Critical: true,
				Value:    []byte{goasn1.TagSequence | bit6, 3, goasn1.TagBoolean, 1, 0xff},
			},
		},
		{
			name: "CA/MaxPathLen",
			ext:  extensions.BasicConstraints{Critical: true, IsCA: true, MaxPathLen: 4},
			want: pkix.Extension{
				Id:       asn1.OIDBasicConstraints,
				Critical: true,
				Value:    []byte{goasn1.TagSequence | bit6, 6, goasn1.TagBoolean, 1, 0xff, goasn1.TagInteger, 1, 4},
			},
		},
	}

	for _, tc := range testcases {
		var tc = tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := tc.ext.Marshal()
			if err != nil {
				t.Fatalf("couldn't marshal basic constraints: %v", err)
			}

			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
}

func TestBasicConstraintsUnmarshal(t *testing.T) {
	t.Parallel()

	var testcases = []struct {
		name string
		ext  pkix.Extension
		want extensions.BasicConstraints
		err  error
	}{
		{
			name: "NotCA",
			ext: pkix.Extension{
				Id:       asn1.OIDBasicConstraints,
				Critical: false,
				Value:    []byte{goasn1.TagSequence | bit6, 3, goasn1.TagBoolean, 1, 0x0},
			},
			want: extensions.BasicConstraints{MaxPathLen: -1},
		},
		{
			name: "CA/NoMaxPathLen",
			ext: pkix.Extension{
				Id:       asn1.OIDBasicConstraints,
				Critical: true,
				Value:    []byte{goasn1.TagSequence | bit6, 3, goasn1.TagBoolean, 1, 0xff},
			},
			want: extensions.BasicConstraints{Critical: true, IsCA: true, MaxPathLen: -1},
		},
		{
			name: "CA/MaxPathLen",
			ext: pkix.Extension{
				Id:       asn1.OIDBasicConstraints,
				Critical: true,
				Value:    []byte{goasn1.TagSequence | bit6, 6, goasn1.TagBoolean, 1, 0xff, goasn1.TagInteger, 1, 4},
			},
			want: extensions.BasicConstraints{Critical: true, IsCA: true, MaxPathLen: 4},
		},
		{
			name: "BadOID",
			ext: pkix.Extension{
				Id:       asn1.OIDSubjectAltName,
				Critical: false,
				Value:    []byte{goasn1.TagSequence | bit6, 3, goasn1.TagBoolean, 1, 0x0},
			},
			want: extensions.BasicConstraints{},
			err:  errors.New("bad OID"),
		},
	}

	for _, tc := range testcases {
		var tc = tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var got extensions.BasicConstraints

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
