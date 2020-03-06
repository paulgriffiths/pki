package pki

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"fmt"
)

// PublicKeyFromPrivateKey returns the public key corresponding to a private
// key.
func PublicKeyFromPrivateKey(priv interface{}) (crypto.PublicKey, error) {
	switch t := priv.(type) {
	case rsa.PrivateKey:
		return t.Public(), nil

	case *rsa.PrivateKey:
		return t.Public(), nil

	case ecdsa.PrivateKey:
		return t.Public(), nil

	case *ecdsa.PrivateKey:
		return t.Public(), nil

	case ed25519.PrivateKey:
		return t.Public(), nil

	case *ed25519.PrivateKey:
		return t.Public(), nil
	}

	return nil, fmt.Errorf("unsupported private key type: %T", priv)
}
