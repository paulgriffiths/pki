package asn1

import (
	goasn1 "encoding/asn1"
	"strconv"
	"strings"
)

// OID constants.
var (
	OIDKeyUsage         = goasn1.ObjectIdentifier{2, 5, 29, 15}
	OIDSubjectAltName   = goasn1.ObjectIdentifier{2, 5, 29, 17}
	OIDBasicConstraints = goasn1.ObjectIdentifier{2, 5, 29, 19}
	OIDExtendedKeyUsage = goasn1.ObjectIdentifier{2, 5, 29, 37}
)

// ParseOID parses a dotted decimal string representation of an OID.
func ParseOID(s string) (goasn1.ObjectIdentifier, error) {
	var id goasn1.ObjectIdentifier

	for _, element := range strings.Split(s, ".") {
		n, err := strconv.ParseUint(element, 10, strconv.IntSize)
		if err != nil {
			return nil, err
		}
		id = append(id, int(n))
	}

	return id, nil
}
