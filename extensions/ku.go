package extensions

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"fmt"
	"math/bits"

	pgasn1 "github.com/paulgriffiths/pki/asn1"
)

// KeyUsage represents an X509 key usage extension as defined in RFC5280
// section 4.2.1.3.
type KeyUsage struct {
	Critical bool
	Value    x509.KeyUsage
}

// Marshal returns a pkix.Extension.
func (e KeyUsage) Marshal() (pkix.Extension, error) {

	// When the keyUsage extension appears in a certificate, at least one of
	// the bits MUST be set to 1. See RFC5280 section 4.2.1.3.
	if e.Value == 0 {
		return pkix.Extension{}, errors.New("no key usages specified")
	}

	bs := asn1.BitString{
		BitLength: 9,
		Bytes:     make([]byte, 2),
	}
	binary.BigEndian.PutUint16(bs.Bytes, bits.Reverse16(uint16(e.Value)))

	der, err := asn1.Marshal(bs)
	if err != nil {
		return pkix.Extension{}, err
	}

	return pkix.Extension{
		Id:       pgasn1.OIDKeyUsage,
		Critical: e.Critical,
		Value:    der,
	}, nil
}

// Unmarshal parses a pkix.Extension and stores the result in the object.
func (e *KeyUsage) Unmarshal(ext pkix.Extension) error {
	if !ext.Id.Equal(pgasn1.OIDKeyUsage) {
		return fmt.Errorf("unexpected OID: %v", ext.Id)
	}

	var bs asn1.BitString
	if rest, err := asn1.Unmarshal(ext.Value, &bs); err != nil {
		return err
	} else if len(rest) > 0 {
		return ErrTrailingBytes
	}

	*e = KeyUsage{
		Critical: ext.Critical,
		Value:    x509.KeyUsage(bits.Reverse16(binary.BigEndian.Uint16(bs.Bytes)) & 0x1ff),
	}

	return nil
}
