package asn1_test

import (
	"bytes"
	"errors"
	"reflect"
	"testing"

	goasn1 "encoding/asn1"

	"github.com/paulgriffiths/pki/asn1"
)

const bit6 = 0x01 << 5

func TestBasicConstraintsMarshal(t *testing.T) {
	t.Parallel()

	var testcases = []struct {
		name string
		obj  asn1.BasicConstraints
		want []byte
	}{
		{
			name: "NotCA",
			obj:  asn1.BasicConstraints{},
			want: []byte{goasn1.TagSequence | bit6, 3, goasn1.TagBoolean, 1, 0x0},
		},
		{
			name: "CA/NoMaxPathLen",
			obj:  asn1.BasicConstraints{IsCA: true, MaxPathLen: -1},
			want: []byte{goasn1.TagSequence | bit6, 3, goasn1.TagBoolean, 1, 0xff},
		},
		{
			name: "CA/MaxPathLen",
			obj:  asn1.BasicConstraints{IsCA: true, MaxPathLen: 4},
			want: []byte{goasn1.TagSequence | bit6, 6, goasn1.TagBoolean, 1, 0xff, goasn1.TagInteger, 1, 4},
		},
	}

	for _, tc := range testcases {
		var tc = tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := tc.obj.Marshal()
			if err != nil {
				t.Fatalf("couldn't marshal basic constraints: %v", err)
			}

			if !bytes.Equal(got, tc.want) {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
}

func TestBasicConstraintsUnmarshal(t *testing.T) {
	t.Parallel()

	var testcases = []struct {
		name string
		der  []byte
		want asn1.BasicConstraints
		err  error
	}{
		{
			name: "NotCA",
			der:  []byte{goasn1.TagSequence | bit6, 3, goasn1.TagBoolean, 1, 0x0},
			want: asn1.BasicConstraints{IsCA: false, MaxPathLen: -1},
		},
		{
			name: "CA/NoMaxPathLen",
			der:  []byte{goasn1.TagSequence | bit6, 3, goasn1.TagBoolean, 1, 0xff},
			want: asn1.BasicConstraints{IsCA: true, MaxPathLen: -1},
		},
		{
			name: "CA/MaxPathLen",
			der:  []byte{goasn1.TagSequence | bit6, 6, goasn1.TagBoolean, 1, 0xff, goasn1.TagInteger, 1, 4},
			want: asn1.BasicConstraints{IsCA: true, MaxPathLen: 4},
		},
		{
			name: "TrailingData",
			der:  []byte{goasn1.TagSequence | bit6, 6, goasn1.TagBoolean, 1, 0xff, goasn1.TagInteger, 1, 4, 0xff},
			want: asn1.BasicConstraints{},
			err:  errors.New("trailing data"),
		},
		{
			name: "BadASN1",
			der:  []byte{0xff, 0xff, 0xff},
			want: asn1.BasicConstraints{},
			err:  errors.New("bad ASN.1"),
		},
	}

	for _, tc := range testcases {
		var tc = tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var got asn1.BasicConstraints

			err := got.Unmarshal(tc.der)
			if (err == nil) != (tc.err == nil) {
				t.Fatalf("got error %v, want %v", err, tc.err)
			}

			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
}
