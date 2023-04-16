package crypto

import (
	"crypto/ecdh"
	"crypto/rand"
)

type ECDHState struct {
	RemotePublicKey *ecdh.PublicKey
	PublicKey       *ecdh.PublicKey
	privateKey      *ecdh.PrivateKey
}

func (e *ECDHState) SetRemotePublicKey(pubKey []byte) {
	curveP256 := ecdh.P256()
	remotePubKey, err := curveP256.NewPublicKey(pubKey)
	if err != nil {
		panic(err.Error())
	}
	e.RemotePublicKey = remotePubKey
}

func (e *ECDHState) GenerateKeyPair() {
	curveP256 := ecdh.P256()
	e.privateKey, _ = curveP256.GenerateKey(rand.Reader)
	e.PublicKey = e.privateKey.PublicKey()
}

func (e *ECDHState) GetSharedSecret() []byte {
	sharedSecret, _ := e.privateKey.ECDH(e.RemotePublicKey)
	return sharedSecret
}
