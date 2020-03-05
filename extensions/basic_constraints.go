package extensions

import (
	"crypto/x509/pkix"
	"fmt"

	"github.com/paulgriffiths/pki/asn1"
)

// BasicConstraints represents an X509 basic constraints extension as defined
// in RFC 5280 section 4.2.1.9.
type BasicConstraints struct {
	Critical   bool
	IsCA       bool
	MaxPathLen int
}

// Marshal returns a pkix.Extension.
func (e BasicConstraints) Marshal() (pkix.Extension, error) {
	var ae = asn1.BasicConstraints{
		IsCA:       e.IsCA,
		MaxPathLen: e.MaxPathLen,
	}

	der, err := ae.Marshal()
	if err != nil {
		return pkix.Extension{}, err
	}

	return pkix.Extension{
		Id:       asn1.OIDBasicConstraints,
		Critical: e.Critical,
		Value:    der,
	}, nil
}

// Unmarshal parses a pkix.Extension and stores the result in the object.
func (e *BasicConstraints) Unmarshal(ext pkix.Extension) error {
	if !ext.Id.Equal(asn1.OIDBasicConstraints) {
		return fmt.Errorf("unexpected OID: %v", ext.Id)
	}

	var ae asn1.BasicConstraints
	if err := ae.Unmarshal(ext.Value); err != nil {
		return err
	}

	*e = BasicConstraints{
		Critical:   ext.Critical,
		IsCA:       ae.IsCA,
		MaxPathLen: ae.MaxPathLen,
	}

	return nil
}
