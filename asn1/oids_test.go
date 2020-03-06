package asn1_test

import (
	"encoding/asn1"
	"errors"
	"testing"

	pgasn1 "github.com/paulgriffiths/pki/asn1"
)

func TestParseOID(t *testing.T) {
	t.Parallel()

	var testcases = []struct {
		s    string
		want asn1.ObjectIdentifier
		err  error
	}{
		{
			s:    "1.2.3.4",
			want: asn1.ObjectIdentifier{1, 2, 3, 4},
		},
		{
			s:   "not an OID",
			err: errors.New("not an OID"),
		},
	}

	for _, tc := range testcases {
		var tc = tc

		t.Run(tc.s, func(t *testing.T) {
			got, err := pgasn1.ParseOID(tc.s)
			if (err == nil) != (tc.err == nil) {
				t.Fatalf("got error %v, want %v", err, tc.err)
			}

			if !got.Equal(tc.want) {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
}
