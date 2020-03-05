package asn1

import (
	goasn1 "encoding/asn1"
)

// OID constants.
var (
	OIDSubjectAltName   = goasn1.ObjectIdentifier{2, 5, 29, 17}
	OIDBasicConstraints = goasn1.ObjectIdentifier{2, 5, 29, 19}
)
