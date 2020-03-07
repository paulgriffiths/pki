package extensions

import (
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"

	"encoding/asn1"

	pgasn1 "github.com/paulgriffiths/pki/asn1"
)

// AuthorityKeyIdentifier represents an X509 authority key identifier extension
// as defined in RFC 5280 section 4.2.1.1.
type AuthorityKeyIdentifier struct {
	Critical     bool
	ID           []byte
	Issuer       asn1.RawValue
	SerialNumber *big.Int
}

// Marshal returns a pkix.Extension.
func (e AuthorityKeyIdentifier) Marshal() (pkix.Extension, error) {
	if len(e.ID) == 0 {
		return pkix.Extension{}, errors.New("no identifier specified")
	}

	var ae = pgasn1.AuthorityKeyIdentifier{
		ID:           e.ID,
		Issuer:       e.Issuer,
		SerialNumber: e.SerialNumber,
	}

	der, err := asn1.Marshal(ae)
	if err != nil {
		return pkix.Extension{}, err
	}

	return pkix.Extension{
		Id:       pgasn1.OIDAuthorityKeyIdentifier,
		Critical: e.Critical,
		Value:    der,
	}, nil
}

// Unmarshal parses a pkix.Extension and stores the result in the object.
func (e *AuthorityKeyIdentifier) Unmarshal(ext pkix.Extension) error {
	if !ext.Id.Equal(pgasn1.OIDAuthorityKeyIdentifier) {
		return fmt.Errorf("unexpected OID: %v", ext.Id)
	}

	var ae pgasn1.AuthorityKeyIdentifier
	if rest, err := asn1.Unmarshal(ext.Value, &ae); err != nil {
		return err
	} else if len(rest) > 0 {
		// We should never get here when unmarshalling to a slice of bytes,
		// but we may as well retain it for good form.
		return ErrTrailingBytes
	}

	*e = AuthorityKeyIdentifier{
		Critical:     ext.Critical,
		ID:           ae.ID,
		Issuer:       ae.Issuer,
		SerialNumber: ae.SerialNumber,
	}

	return nil
}
