package extensions

import (
	"crypto/x509/pkix"
	"fmt"
	"net"
	"net/url"

	"github.com/paulgriffiths/pki/asn1"
)

// SubjectAltName represents a subject alternative name extension as defined
// in RFC5280 section 4.2.1.6.
type SubjectAltName struct {
	Critical       bool
	DNSNames       []string
	EmailAddresses []string
	IPAddresses    []net.IP
	URIs           []*url.URL
}

// Marshal returns a pkix.Extension.
func (e SubjectAltName) Marshal() (pkix.Extension, error) {
	der, err := asn1.GeneralNames{
		DNSNames:       e.DNSNames,
		EmailAddresses: e.EmailAddresses,
		IPAddresses:    e.IPAddresses,
		URIs:           e.URIs,
	}.Marshal()
	if err != nil {
		return pkix.Extension{}, nil
	}

	return pkix.Extension{
		Id:       asn1.OIDSubjectAltName,
		Critical: e.Critical,
		Value:    der,
	}, nil
}

// Unmarshal parses a pkix.Extension and stores the result in the object.
func (e *SubjectAltName) Unmarshal(ext pkix.Extension) error {
	if !ext.Id.Equal(asn1.OIDSubjectAltName) {
		return fmt.Errorf("unexpected OID: %v", ext.Id)
	}

	var ae asn1.GeneralNames
	if err := ae.Unmarshal(ext.Value); err != nil {
		return err
	}

	*e = SubjectAltName{
		Critical:       ext.Critical,
		DNSNames:       ae.DNSNames,
		EmailAddresses: ae.EmailAddresses,
		IPAddresses:    ae.IPAddresses,
		URIs:           ae.URIs,
	}

	return nil
}
