package crypto

import (
	"crypto/sha256"
	"golang.org/x/crypto/hkdf"
	"io"
)

func HKDF(secret []byte, salt []byte) []byte {
	hash := sha256.New
	hkdf := hkdf.New(hash, secret, salt, nil)
	key := make([]byte, 16)
	if _, err := io.ReadFull(hkdf, key); err != nil {
		panic(err)
	}
	return key
}
