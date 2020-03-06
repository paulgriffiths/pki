package pkifile

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
)

var (
	// ErrNonPEMData indicates that a file expected to contain only PEM blocks
	// contains other data.
	ErrNonPEMData = errors.New("non-PEM data in file")

	// ErrTrailingData indicates that a file contains trailing data after one
	// or more PEM blocks.
	ErrTrailingData = errors.New("trailing data in file")

	// ErrUnrecognizedKeyType indicates that a file contained a PEM block with
	// an unrecognized key type.
	ErrUnrecognizedKeyType = errors.New("unrecognized key type")
)

// PEMBlockFromFile reads a PEM block from a file. An error is returned if the
// file is empty, or if it contains any data other than a single PEM block.
func PEMBlockFromFile(filename string) (*pem.Block, error) {
	b, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	block, rest := pem.Decode(b)
	if block == nil {
		return nil, ErrNonPEMData
	}
	if len(rest) > 0 {
		return nil, ErrTrailingData
	}

	return block, nil
}

// PEMBlocksFromFile reads a slice of PEM blocks from a file. An error is returned
// if the file is empty, or if it contains any data other than a sequence of PEM
// blocks.
func PEMBlocksFromFile(filename string) ([]*pem.Block, error) {
	rest, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	var blocks = []*pem.Block{}

	for len(rest) > 0 {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			if len(blocks) == 0 {
				return nil, ErrNonPEMData
			}

			return nil, ErrTrailingData
		}
		blocks = append(blocks, block)
	}

	if len(blocks) == 0 {
		return nil, ErrNonPEMData
	}

	return blocks, nil
}

// PrivateKeyFromPEMFile reads a single PEM-encoded private key from a file.
// PKCS1 RSA private keys, SEC1 EC private keys, and PKCS8 RSA and EC private
// keys are supported.
func PrivateKeyFromPEMFile(filename string) (interface{}, error) {
	block, err := PEMBlockFromFile(filename)
	if err != nil {
		return nil, err
	}

	switch block.Type {
	case "PRIVATE KEY":
		return x509.ParsePKCS8PrivateKey(block.Bytes)

	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(block.Bytes)

	case "EC PRIVATE KEY":
		return x509.ParseECPrivateKey(block.Bytes)
	}

	return nil, ErrUnrecognizedKeyType
}

// PublicKeyFromPEMFile reads a single PEM-encoded public key from a file.
// PKCS1 RSA public keys, and PKIX RSA and EC public keys are supported.
func PublicKeyFromPEMFile(filename string) (interface{}, error) {
	block, err := PEMBlockFromFile(filename)
	if err != nil {
		return nil, err
	}

	switch block.Type {
	case "PUBLIC KEY":
		return x509.ParsePKIXPublicKey(block.Bytes)

	case "RSA PUBLIC KEY":
		return x509.ParsePKCS1PublicKey(block.Bytes)
	}

	return nil, ErrUnrecognizedKeyType
}

// CertFromPEMFile reads a single PEM-encoded X509 certificate from a file.
func CertFromPEMFile(filename string) (*x509.Certificate, error) {
	block, err := PEMBlockFromFile(filename)
	if err != nil {
		return nil, err
	}

	if block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("got PEM header %s, expected CERTIFICATE", block.Type)
	}

	return x509.ParseCertificate(block.Bytes)
}

// CertsFromPEMFile reads one or more PEM-encoded X509 certificates from a
// file.
func CertsFromPEMFile(filename string) ([]*x509.Certificate, error) {
	blocks, err := PEMBlocksFromFile(filename)
	if err != nil {
		return nil, err
	}

	var certs []*x509.Certificate

	for _, block := range blocks {
		if block.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("got PEM header %s, expected CERTIFICATE", block.Type)
		}

		crt, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}

		certs = append(certs, crt)
	}

	return certs, nil
}

// CSRFromPEMFile reads a single PEM-encoded PKCS10 certificate signing
// request from a file.
func CSRFromPEMFile(filename string) (*x509.CertificateRequest, error) {
	block, err := PEMBlockFromFile(filename)
	if err != nil {
		return nil, err
	}

	if block.Type != "CERTIFICATE REQUEST" && block.Type != "NEW CERTIFICATE REQUEST" {
		return nil, fmt.Errorf("got PEM header %s, expected CERTIFICATE REQUEST", block.Type)
	}

	return x509.ParseCertificateRequest(block.Bytes)
}
