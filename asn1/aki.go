package asn1

import (
	"encoding/asn1"
	"errors"
	"math/big"
)

// AuthorityKeyIdentifier represents an X509 authority key identifier
// extension as defined in RFC 5280 section 4.2.1.1.
//
// id-ce-authorityKeyIdentifier OBJECT IDENTIFIER ::=  { id-ce 35 }
//
//  AuthorityKeyIdentifier ::= SEQUENCE {
//     keyIdentifier             [0] KeyIdentifier           OPTIONAL,
//     authorityCertIssuer       [1] GeneralNames            OPTIONAL,
//     authorityCertSerialNumber [2] CertificateSerialNumber OPTIONAL  }
//
//  KeyIdentifier ::= OCTET STRING
type AuthorityKeyIdentifier struct {
	ID           []byte        `asn1:"optional,tag:0"`
	Issuer       asn1.RawValue `asn1:"optional,tag:1"`
	SerialNumber *big.Int      `asn1:"optional,tag:2"`
}

// Marshal returns the ASN.1 DER-encoding of a value.
func (e AuthorityKeyIdentifier) Marshal() ([]byte, error) {
	return asn1.Marshal(e)
}

// Unmarshal parses an DER-encoded ASN.1 data structure and stores the result
// in the object.
func (e *AuthorityKeyIdentifier) Unmarshal(b []byte) error {
	var tmp AuthorityKeyIdentifier

	rest, err := asn1.Unmarshal(b, &tmp)
	if err != nil {
		return err
	} else if len(rest) != 0 {
		return errors.New("trailing bytes")
	}

	*e = tmp

	return nil
}
