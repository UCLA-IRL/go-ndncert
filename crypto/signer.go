package crypto

import (
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/sha256"
	enc "github.com/zjkmxy/go-ndn/pkg/encoding"
	"github.com/zjkmxy/go-ndn/pkg/ndn"
	"github.com/zjkmxy/go-ndn/pkg/utils"
	"time"
)

ndncertSigner is a signer that uses a provided ECDSA key.
type ndncertSigner struct {
	keyName   enc.Name
	key       *ecdsa.PrivateKey
	notBefore *time.Time
	notAfter  *time.Time
}

func (signer *ndncertSigner) SigInfo() (*ndn.SigConfig, error) {
	return &ndn.SigConfig{
		Type:      ndn.SignatureHmacWithSha256,
		KeyName:   signer.keyName,
		NotBefore: signer.notBefore,
		NotAfter:  signer.notAfter,
	}, nil
}

func (*ndncertSigner) EstimateSize() uint {
	return 32
}

func (signer *ndncertSigner) ComputeSigValue(covered enc.Wire) ([]byte, error) {
	mac := hmac.New(sha256.New, signer.key)
	for _, buf := range covered {
		_, err := mac.Write(buf)
		if err != nil {
			return nil, enc.ErrUnexpected{Err: err}
		}
	}
	return mac.Sum(nil), nil
}

// NewNDNCertSigner creates a Certificate signer that uses DigestSha256.
func NewNDNCertSigner(keyName enc.Name, key []byte, notBefore *time.Time, notAfter *time.Time) ndn.Signer {
	return &ndncertSigner{
		keyName:   keyName,
		key:       key,
		notBefore: notBefore,
		notAfter:  notAfter,
	}
}

// ndncertIntSigner is a Interest signer that uses a provided HMAC key.
type ndncertIntSigner struct {
	key   []byte
	timer ndn.Timer
	seq   uint64
}

func (signer *ndncertIntSigner) SigInfo() (*ndn.SigConfig, error) {
	return &ndn.SigConfig{
		Type:    ndn.SignatureHmacWithSha256,
		KeyName: enc.Name{enc.Component{Typ: enc.TypeGenericNameComponent, Val: signer.key}},
		Nonce:   signer.timer.Nonce(),
		SigTime: utils.IdPtr(signer.timer.Now()),
		SeqNum:  utils.IdPtr(signer.seq),
	}, nil
}

func (*ndncertIntSigner) EstimateSize() uint {
	return 32
}

func (signer *ndncertIntSigner) ComputeSigValue(covered enc.Wire) ([]byte, error) {
	mac := hmac.New(sha256.New, signer.key)
	for _, buf := range covered {
		_, err := mac.Write(buf)
		if err != nil {
			return nil, enc.ErrUnexpected{Err: err}
		}
	}
	return mac.Sum(nil), nil
}

// NewCertIntSigner creates an Interest signer that uses DigestSha256.
func NewCertIntSigner(key []byte, timer ndn.Timer) ndn.Signer {
	return &ndncertIntSigner{key, timer, 0}
}

func CheckCertSig(sigCovered enc.Wire, sigValue []byte, key []byte) bool {
	mac := hmac.New(sha256.New, key)
	for _, buf := range sigCovered {
		_, err := mac.Write(buf)
		if err != nil {
			return false
		}
	}
	return hmac.Equal(mac.Sum(nil), sigValue)
}
