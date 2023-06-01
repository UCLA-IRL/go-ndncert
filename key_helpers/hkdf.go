package key_helpers

import (
	"crypto/sha256"
	"golang.org/x/crypto/hkdf"
	"io"
)

type RequestId [8]byte

func HKDF(secret []byte, salt []byte, requestId RequestId) []byte {
	hash := sha256.New
	hkdf := hkdf.New(hash, secret, salt, requestId[:])
	key := make([]byte, 16)
	if _, err := io.ReadFull(hkdf, key); err != nil {
		panic(err)
	}
	return key
}
