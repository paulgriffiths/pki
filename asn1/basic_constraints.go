package asn1

import (
	"encoding/asn1"
	"errors"
)

// BasicConstraints represents an X509 basic constraints extension as defined
// in RFC 5280 section 4.2.1.9.
//
// id-ce-basicConstraints OBJECT IDENTIFIER ::=  { id-ce 19 }
//
// BasicConstraints ::= SEQUENCE {
//      cA                      BOOLEAN DEFAULT FALSE,
//      pathLenConstraint       INTEGER (0..MAX) OPTIONAL }
type BasicConstraints struct {
	IsCA       bool `asn1:"optional"`
	MaxPathLen int  `asn1:"optional,default:-1"`
}

// Marshal returns the ASN.1 DER-encoding of a value.
func (e BasicConstraints) Marshal() ([]byte, error) {
	if !e.IsCA || e.MaxPathLen == -1 {
		var tmp = struct {
			IsCA bool
		}{
			IsCA: e.IsCA,
		}

		return asn1.Marshal(tmp)
	}

	return asn1.Marshal(e)
}

// Unmarshal parses an DER-encoded ASN.1 data structure and stores the result
// in the object.
func (e *BasicConstraints) Unmarshal(b []byte) error {
	var tmp BasicConstraints

	rest, err := asn1.Unmarshal(b, &tmp)
	if err != nil {
		return err
	} else if len(rest) != 0 {
		return errors.New("trailing bytes")
	}

	*e = tmp

	return nil
}
