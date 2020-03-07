package asn1

import (
	goasn1 "encoding/asn1"
	"strconv"
	"strings"
)

// Extension OID values.
var (
	OIDSubjectKeyIdentifier   = goasn1.ObjectIdentifier{2, 5, 29, 14}
	OIDKeyUsage               = goasn1.ObjectIdentifier{2, 5, 29, 15}
	OIDSubjectAltName         = goasn1.ObjectIdentifier{2, 5, 29, 17}
	OIDBasicConstraints       = goasn1.ObjectIdentifier{2, 5, 29, 19}
	OIDAuthorityKeyIdentifier = goasn1.ObjectIdentifier{2, 5, 29, 35}
	OIDExtendedKeyUsage       = goasn1.ObjectIdentifier{2, 5, 29, 37}
)

// Signature and hash OID values.
var (
	OIDSignatureMD2WithRSA      = goasn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 2}
	OIDSignatureMD5WithRSA      = goasn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 4}
	OIDSignatureSHA1WithRSA     = goasn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 5}
	OIDSignatureSHA256WithRSA   = goasn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}
	OIDSignatureSHA384WithRSA   = goasn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 12}
	OIDSignatureSHA512WithRSA   = goasn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 13}
	OIDSignatureRSAPSS          = goasn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 10}
	OIDSignatureDSAWithSHA1     = goasn1.ObjectIdentifier{1, 2, 840, 10040, 4, 3}
	OIDSignatureDSAWithSHA256   = goasn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 2}
	OIDSignatureECDSAWithSHA1   = goasn1.ObjectIdentifier{1, 2, 840, 10045, 4, 1}
	OIDSignatureECDSAWithSHA256 = goasn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
	OIDSignatureECDSAWithSHA384 = goasn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 3}
	OIDSignatureECDSAWithSHA512 = goasn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 4}
	OIDSignatureEd25519         = goasn1.ObjectIdentifier{1, 3, 101, 112}

	OIDSHA256 = goasn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	OIDSHA384 = goasn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}
	OIDSHA512 = goasn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}

	OIDMGF1 = goasn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 8}

	OIDISOSignatureSHA1WithRSA = goasn1.ObjectIdentifier{1, 3, 14, 3, 2, 29}
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
