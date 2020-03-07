package extensions

import (
	"crypto"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"

	"encoding/asn1"

	pgasn1 "github.com/paulgriffiths/pki/asn1"
)

// SubjectKeyIdentifier represents an X509 subject key identifier extension
// as defined in RFC 5280 section 4.2.1.2.
type SubjectKeyIdentifier struct {
	Critical bool
	ID       []byte
}

// Marshal returns a pkix.Extension.
func (e SubjectKeyIdentifier) Marshal() (pkix.Extension, error) {
	if len(e.ID) == 0 {
		return pkix.Extension{}, errors.New("no identifier specified")
	}

	der, err := asn1.Marshal(e.ID)
	if err != nil {
		return pkix.Extension{}, err
	}

	return pkix.Extension{
		Id:       pgasn1.OIDSubjectKeyIdentifier,
		Critical: e.Critical,
		Value:    der,
	}, nil
}

// Unmarshal parses a pkix.Extension and stores the result in the object.
func (e *SubjectKeyIdentifier) Unmarshal(ext pkix.Extension) error {
	if !ext.Id.Equal(pgasn1.OIDSubjectKeyIdentifier) {
		return fmt.Errorf("unexpected OID: %v", ext.Id)
	}

	var id []byte
	if rest, err := asn1.Unmarshal(ext.Value, &id); err != nil {
		return err
	} else if len(rest) > 0 {
		// We should never get here when unmarshalling to a slice of bytes,
		// but we may as well retain it for good form.
		return ErrTrailingBytes
	}

	*e = SubjectKeyIdentifier{
		Critical: ext.Critical,
		ID:       id,
	}

	return nil
}

// MakePublicKeyIdentifier builds a public key identifier in accordance with the
// first method described in RFC5280 section 4.2.1.2.
func MakePublicKeyIdentifier(pub crypto.PublicKey) ([]byte, error) {
	keyBytes, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}

	id := sha1.Sum(keyBytes)
	return id[:], nil
}
