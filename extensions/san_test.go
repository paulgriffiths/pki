package extensions_test

import (
	"crypto/x509/pkix"
	"errors"
	"net"
	"reflect"
	"testing"

	"encoding/asn1"

	pgasn1 "github.com/paulgriffiths/pki/asn1"
	"github.com/paulgriffiths/pki/extensions"
)

// Tag numbers for GeneralName structure.
const (
	nameTagOtherName     = 0
	nameTagRFC822Name    = 1
	nameTagDNSName       = 2
	nameTagX400Address   = 3
	nameTagDirectoryName = 4
	nameTagEDIPartyName  = 5
	nameTagURI           = 6
	nameTagIPAddress     = 7
	nameTagRegisteredID  = 8
)

func TestSubjectAltNameMarshal(t *testing.T) {
	t.Parallel()

	var testcases = []struct {
		name string
		ext  extensions.SubjectAltName
		want pkix.Extension
		err  error
	}{
		{
			name: "OK",
			ext: extensions.SubjectAltName{
				Critical:    true,
				IPAddresses: []net.IP{net.ParseIP("10.0.0.1")},
			},
			want: pkix.Extension{
				Id:       pgasn1.OIDSubjectAltName,
				Critical: true,
				Value: []byte{asn1.TagSequence | bit6, 6,
					nameTagIPAddress | asn1.ClassContextSpecific<<6, 4, 10, 0, 0, 1,
				},
			},
		},
		{
			name: "Empty",
			ext:  extensions.SubjectAltName{},
			want: pkix.Extension{},
			err:  errors.New("no names"),
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

func TestSubjectAltNameUnmarshal(t *testing.T) {
	t.Parallel()

	var testcases = []struct {
		name string
		ext  pkix.Extension
		want extensions.SubjectAltName
		err  error
	}{
		{
			name: "OK",
			ext: pkix.Extension{
				Id:       pgasn1.OIDSubjectAltName,
				Critical: true,
				Value: []byte{asn1.TagSequence | bit6, 6,
					nameTagIPAddress | asn1.ClassContextSpecific<<6, 4, 10, 0, 0, 1,
				},
			},
			want: extensions.SubjectAltName{
				Critical:    true,
				IPAddresses: []net.IP{net.ParseIP("10.0.0.1").To4()},
			},
		},
		{
			name: "BadOID",
			ext: pkix.Extension{
				Id:       pgasn1.OIDBasicConstraints,
				Critical: true,
				Value: []byte{asn1.TagSequence | bit6, 6,
					nameTagIPAddress | asn1.ClassContextSpecific<<6, 4, 10, 0, 0, 1,
				},
			},
			want: extensions.SubjectAltName{},
			err:  errors.New("bad OID"),
		},
	}

	for _, tc := range testcases {
		var tc = tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var got extensions.SubjectAltName

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
