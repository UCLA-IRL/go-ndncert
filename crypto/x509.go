package crypto

import (
	"crypto/ecdsa"
	"crypto/x509"
)

func EncodePublicKey(key *ecdsa.PublicKey) ([]byte, error) {
	return x509.MarshalPKIXPublicKey(key)
}

func ParsePublicKey(der []byte) (*ecdsa.PublicKey, error) {
	genericPublicKey, parsePublicKeyError := x509.ParsePKIXPublicKey(der)
	return genericPublicKey.(*ecdsa.PublicKey), parsePublicKeyError
}
