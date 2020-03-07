package asn1_test

import (
	"bytes"
	"errors"
	"net"
	"net/url"
	"reflect"
	"testing"

	"encoding/asn1"

	pgasn1 "github.com/paulgriffiths/pki/asn1"
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

func TestGeneralNamesMarshal(t *testing.T) {
	t.Parallel()

	var testcases = []struct {
		name string
		obj  pgasn1.GeneralNames
		want []byte
		err  error
	}{
		{
			name: "Full",
			obj: pgasn1.GeneralNames{
				DNSNames:       []string{"some.domain", "foo.bar"},
				EmailAddresses: []string{"foo@bar", "tom@jerry"},
				IPAddresses: []net.IP{
					net.ParseIP("10.0.0.1"),
					net.ParseIP("::1"),
				},
				URIs: []*url.URL{
					mustParseURI(t, "http://www.this"),
					mustParseURI(t, "ftp://ftp.that"),
				},
			},
			want: []byte{asn1.TagSequence | bit6, 99,
				nameTagDNSName | asn1.ClassContextSpecific<<6, 11, 's', 'o', 'm', 'e', '.', 'd', 'o', 'm', 'a', 'i', 'n',
				nameTagDNSName | asn1.ClassContextSpecific<<6, 7, 'f', 'o', 'o', '.', 'b', 'a', 'r',
				nameTagRFC822Name | asn1.ClassContextSpecific<<6, 7, 'f', 'o', 'o', '@', 'b', 'a', 'r',
				nameTagRFC822Name | asn1.ClassContextSpecific<<6, 9, 't', 'o', 'm', '@', 'j', 'e', 'r', 'r', 'y',
				nameTagIPAddress | asn1.ClassContextSpecific<<6, 4, 10, 0, 0, 1,
				nameTagIPAddress | asn1.ClassContextSpecific<<6, 16, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
				nameTagURI | asn1.ClassContextSpecific<<6, 15, 'h', 't', 't', 'p', ':',
				'/', '/', 'w', 'w', 'w', '.', 't', 'h', 'i', 's',
				nameTagURI | asn1.ClassContextSpecific<<6, 14, 'f', 't', 'p', ':',
				'/', '/', 'f', 't', 'p', '.', 't', 'h', 'a', 't',
			},
		},
		{
			name: "NotIA5String/DNSNames",
			obj: pgasn1.GeneralNames{
				DNSNames: []string{"\xff"},
			},
			err: errors.New("not IA5String"),
		},
		{
			name: "NotIA5String/EmailAddresses",
			obj: pgasn1.GeneralNames{
				EmailAddresses: []string{"\xff"},
			},
			err: errors.New("not IA5String"),
		},
		{
			name: "NotDomainName",
			obj: pgasn1.GeneralNames{
				DNSNames: []string{"..."},
			},
			err: errors.New("not domain name"),
		},
		{
			name: "NotRFC822Name",
			obj: pgasn1.GeneralNames{
				EmailAddresses: []string{"dog"},
			},
			err: errors.New("not RFC822 name"),
		},
	}

	for _, tc := range testcases {
		var tc = tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := tc.obj.Marshal()
			if (err == nil) != (tc.err == nil) {
				t.Fatalf("got error %v, want %v", err, tc.err)
			}

			if !bytes.Equal(got, tc.want) {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
}

func TestGeneralNamesUnmarshal(t *testing.T) {
	t.Parallel()

	var testcases = []struct {
		name string
		obj  []byte
		want pgasn1.GeneralNames
		err  error
	}{
		{
			name: "Full",
			obj: []byte{asn1.TagSequence | bit6, 99,
				nameTagDNSName | asn1.ClassContextSpecific<<6, 11, 's', 'o', 'm', 'e', '.', 'd', 'o', 'm', 'a', 'i', 'n',
				nameTagDNSName | asn1.ClassContextSpecific<<6, 7, 'f', 'o', 'o', '.', 'b', 'a', 'r',
				nameTagRFC822Name | asn1.ClassContextSpecific<<6, 7, 'f', 'o', 'o', '@', 'b', 'a', 'r',
				nameTagRFC822Name | asn1.ClassContextSpecific<<6, 9, 't', 'o', 'm', '@', 'j', 'e', 'r', 'r', 'y',
				nameTagIPAddress | asn1.ClassContextSpecific<<6, 4, 10, 0, 0, 1,
				nameTagIPAddress | asn1.ClassContextSpecific<<6, 16, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
				nameTagURI | asn1.ClassContextSpecific<<6, 15, 'h', 't', 't', 'p', ':',
				'/', '/', 'w', 'w', 'w', '.', 't', 'h', 'i', 's',
				nameTagURI | asn1.ClassContextSpecific<<6, 14, 'f', 't', 'p', ':',
				'/', '/', 'f', 't', 'p', '.', 't', 'h', 'a', 't',
			},
			want: pgasn1.GeneralNames{
				DNSNames:       []string{"some.domain", "foo.bar"},
				EmailAddresses: []string{"foo@bar", "tom@jerry"},
				IPAddresses: []net.IP{
					net.ParseIP("10.0.0.1").To4(),
					net.ParseIP("::1"),
				},
				URIs: []*url.URL{
					mustParseURI(t, "http://www.this"),
					mustParseURI(t, "ftp://ftp.that"),
				},
			},
		},
		{
			name: "BadASN1",
			obj:  []byte{0xff},
			err:  errors.New("bad ASN.1"),
		},
		{
			name: "TrailingBytes",
			obj: []byte{asn1.TagSequence | bit6, 6,
				nameTagIPAddress | asn1.ClassContextSpecific<<6, 4, 10, 0, 0, 1, 0xff},
			err: errors.New("trailing bytes"),
		},
		{
			name: "BadIPAddress",
			obj: []byte{asn1.TagSequence | bit6, 7,
				nameTagIPAddress | asn1.ClassContextSpecific<<6, 5, 10, 0, 0, 1, 1},
			err: errors.New("bad IP address"),
		},
		{
			name: "BadURI",
			obj: []byte{asn1.TagSequence | bit6, 5,
				nameTagURI | asn1.ClassContextSpecific<<6, 3, '$', '$', ':'},
			err: errors.New("bad URI"),
		},
		{
			name: "BadURIHost",
			obj: []byte{asn1.TagSequence | bit6, 14,
				nameTagURI | asn1.ClassContextSpecific<<6, 12, 'h', 't', 't', 'p', ':',
				'/', '/', 'w', 'w', 'w', '.', '.'},
			err: errors.New("bad URI host"),
		},
	}

	for _, tc := range testcases {
		var tc = tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var got pgasn1.GeneralNames

			err := got.Unmarshal(tc.obj)
			if (err == nil) != (tc.err == nil) {
				t.Fatalf("got error %v, want %v", err, tc.err)
			}

			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
}

func mustParseURI(t *testing.T, s string) *url.URL {
	t.Helper()

	uri, err := url.Parse(s)
	if err != nil {
		t.Fatalf("couldn't parse URL: %v", err)
	}

	return uri
}
