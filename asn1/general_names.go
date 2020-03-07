package asn1

import (
	"encoding/asn1"
	"errors"
	"fmt"
	"net"
	"net/url"
)

// GeneralNames represents a General Names sequence as defined in RFC 5820
// section 4.2.1.6.
//
// GeneralNames ::= SEQUENCE SIZE (1..MAX) OF GeneralName
//
// GeneralName ::= CHOICE {
//      otherName                       [0]     OtherName,
//      rfc822Name                      [1]     IA5String,
//      dNSName                         [2]     IA5String,
//      x400Address                     [3]     ORAddress,
//      directoryName                   [4]     Name,
//      ediPartyName                    [5]     EDIPartyName,
//      uniformResourceIdentifier       [6]     IA5String,
//      iPAddress                       [7]     OCTET STRING,
//      registeredID                    [8]     OBJECT IDENTIFIER }
//
// OtherName ::= SEQUENCE {
//      type-id    OBJECT IDENTIFIER,
//      value      [0] EXPLICIT ANY DEFINED BY type-id }
//
// EDIPartyName ::= SEQUENCE {
//      nameAssigner            [0]     DirectoryString OPTIONAL,
//      partyName               [1]     DirectoryString }
type GeneralNames struct {
	DNSNames       []string
	DirectoryNames []string
	EmailAddresses []string
	IPAddresses    []net.IP
	URIs           []*url.URL
}

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

// Marshal returns the ASN.1 DER-encoding of a value.
func (e GeneralNames) Marshal() ([]byte, error) {
	var vals []asn1.RawValue

	for _, name := range e.DNSNames {
		if err := isIA5String(name); err != nil {
			return nil, err
		}

		if _, ok := domainToReverseLabels(name); !ok {
			return nil, fmt.Errorf("couldn't parse %q as domain name", name)
		}

		vals = append(
			vals,
			asn1.RawValue{
				Tag:   nameTagDNSName,
				Class: asn1.ClassContextSpecific,
				Bytes: []byte(name),
			},
		)
	}

	for _, addr := range e.EmailAddresses {
		if err := isIA5String(addr); err != nil {
			return nil, err
		}

		if _, ok := parseRFC2821Mailbox(addr); !ok {
			return nil, fmt.Errorf("couldn't parse %q as email address", addr)
		}

		vals = append(
			vals,
			asn1.RawValue{
				Tag:   nameTagRFC822Name,
				Class: asn1.ClassContextSpecific,
				Bytes: []byte(addr),
			},
		)
	}

	for _, ip := range e.IPAddresses {
		ipBytes := ip.To4()
		if ipBytes == nil {
			ipBytes = ip
		}

		vals = append(
			vals,
			asn1.RawValue{
				Tag:   nameTagIPAddress,
				Class: asn1.ClassContextSpecific,
				Bytes: ipBytes,
			},
		)
	}

	for _, uri := range e.URIs {
		vals = append(
			vals,
			asn1.RawValue{
				Tag:   nameTagURI,
				Class: asn1.ClassContextSpecific,
				Bytes: []byte(uri.String()),
			},
		)
	}

	return asn1.Marshal(vals)
}

// Unmarshal parses an DER-encoded ASN.1 data structure and stores the result
// in the object.
func (e *GeneralNames) Unmarshal(b []byte) error {
	var tmp GeneralNames
	var vals []asn1.RawValue

	rest, err := asn1.Unmarshal(b, &vals)
	if err != nil {
		return err
	} else if len(rest) != 0 {
		return errors.New("trailing bytes")
	}

	for _, val := range vals {
		switch val.Tag {
		case nameTagDNSName:
			tmp.DNSNames = append(tmp.DNSNames, string(val.Bytes))

		case nameTagRFC822Name:
			tmp.EmailAddresses = append(tmp.EmailAddresses, string(val.Bytes))

		case nameTagIPAddress:
			switch len(val.Bytes) {
			case net.IPv4len, net.IPv6len:
				tmp.IPAddresses = append(tmp.IPAddresses, val.Bytes)

			default:
				return errors.New("cannot parse IP address")
			}

		case nameTagURI:
			uri, err := url.Parse(string(val.Bytes))
			if err != nil {
				return fmt.Errorf("cannot parse %q as URI", string(val.Bytes))
			}
			if len(uri.Host) > 0 {
				if _, ok := domainToReverseLabels(uri.Host); !ok {
					return fmt.Errorf("cannot parse %q as URI", string(val.Bytes))
				}
			}
			tmp.URIs = append(tmp.URIs, uri)
		}
	}

	*e = tmp

	return nil
}
