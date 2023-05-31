package key_helpers

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"math/big"
	"time"
)

func EncodePublicKey(key *ecdsa.PublicKey) ([]byte, error) {
	fmt.Printf("Public key bytes: %+v", key)
	return x509.MarshalPKIXPublicKey(key)
}

func ParsePublicKey(der []byte) (*ecdsa.PublicKey, error) {
	genericPublicKey, parsePublicKeyError := x509.ParsePKIXPublicKey(der)
	if parsePublicKeyError != nil {
		return nil, parsePublicKeyError
	}
	fmt.Printf("Public key bytes: %+v", genericPublicKey)
	return genericPublicKey.(*ecdsa.PublicKey), nil
}

func GenerateCertificate(key *ecdsa.PrivateKey, validitySeconds uint64) ([]byte, error) {
	requesterTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Second * time.Duration(validitySeconds)),
		IsCA:                  false,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	certificateBytes, createCertificateError := x509.CreateCertificate(rand.Reader, requesterTemplate, requesterTemplate, &key.PublicKey, key)
	if createCertificateError != nil {
		return nil, createCertificateError
	}
	return certificateBytes, nil
}

func ParseCertificatePublicKey(der []byte) (*ecdsa.PublicKey, error) {
	certificate, certificateParseError := x509.ParseCertificate(der)
	if certificateParseError != nil {
		return nil, certificateParseError
	}
	genericPublicKey := certificate.PublicKey
	return genericPublicKey.(*ecdsa.PublicKey), nil
}
