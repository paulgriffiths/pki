package asn1

import (
	"encoding/asn1"
	"strconv"
	"strings"
)

// OID constants.
var (
	OIDKeyUsage         = asn1.ObjectIdentifier{2, 5, 29, 15}
	OIDSubjectAltName   = asn1.ObjectIdentifier{2, 5, 29, 17}
	OIDBasicConstraints = asn1.ObjectIdentifier{2, 5, 29, 19}
	OIDExtendedKeyUsage = asn1.ObjectIdentifier{2, 5, 29, 37}
)

// ParseOID parses a dotted decimal string representation of an OID.
func ParseOID(s string) (asn1.ObjectIdentifier, error) {
	var id asn1.ObjectIdentifier

	for _, element := range strings.Split(s, ".") {
		n, err := strconv.ParseUint(element, 10, strconv.IntSize)
		if err != nil {
			return nil, err
		}
		id = append(id, int(n))
	}

	return id, nil
}
