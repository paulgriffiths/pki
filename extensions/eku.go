package extensions

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"

	pgasn1 "github.com/paulgriffiths/pki/asn1"
)

// ExtendedKeyUsage represents an X509 extended key usage extension as defined
// in RFC5280 section 4.2.1.12.
type ExtendedKeyUsage struct {
	Critical bool
	OIDs     []asn1.ObjectIdentifier
}

// Marshal returns a pkix.Extension.
func (e ExtendedKeyUsage) Marshal() (pkix.Extension, error) {
	der, err := asn1.Marshal(e.OIDs)
	if err != nil {
		return pkix.Extension{}, err
	}

	return pkix.Extension{
		Id:       pgasn1.OIDExtendedKeyUsage,
		Critical: e.Critical,
		Value:    der,
	}, nil
}

// Unmarshal parses a pkix.Extension and stores the result in the object.
func (e *ExtendedKeyUsage) Unmarshal(ext pkix.Extension) error {
	if !ext.Id.Equal(pgasn1.OIDExtendedKeyUsage) {
		return fmt.Errorf("unexpected OID: %v", ext.Id)
	}

	var ids []asn1.ObjectIdentifier

	if _, err := asn1.Unmarshal(ext.Value, &ids); err != nil {
		return err
	}

	*e = ExtendedKeyUsage{
		Critical: ext.Critical,
		OIDs:     ids,
	}

	return nil
}
