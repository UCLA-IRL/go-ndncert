package crypto

import (
	"crypto/hmac"
	"crypto/sha256"
	enc "github.com/zjkmxy/go-ndn/pkg/encoding"
	"github.com/zjkmxy/go-ndn/pkg/ndn"
	"github.com/zjkmxy/go-ndn/pkg/utils"
	"time"
)

// certSigner is a Data certificate signer that uses a provided HMAC key.
type certSigner struct {
	keyName   enc.Name
	key       []byte
	notBefore *time.Time
	notAfter  *time.Time
}

func (signer *certSigner) SigInfo() (*ndn.SigConfig, error) {
	return &ndn.SigConfig{
		Type:      ndn.SignatureHmacWithSha256,
		KeyName:   signer.keyName,
		NotBefore: signer.notBefore,
		NotAfter:  signer.notAfter,
	}, nil
}

func (*certSigner) EstimateSize() uint {
	return 32
}

func (signer *certSigner) ComputeSigValue(covered enc.Wire) ([]byte, error) {
	mac := hmac.New(sha256.New, signer.key)
	for _, buf := range covered {
		_, err := mac.Write(buf)
		if err != nil {
			return nil, enc.ErrUnexpected{Err: err}
		}
	}
	return mac.Sum(nil), nil
}

// NewCertSigner creates a Cert signer that uses DigestSha256.
func NewCertSigner(keyName enc.Name, key []byte, notBefore *time.Time, notAfter *time.Time) ndn.Signer {
	return &certSigner{
		keyName:   keyName,
		key:       key,
		notBefore: notBefore,
		notAfter:  notAfter,
	}
}

// hmacIntSigner is a Interest signer that uses a provided HMAC key.
type certIntSigner struct {
	key   []byte
	timer ndn.Timer
	seq   uint64
}

func (signer *certIntSigner) SigInfo() (*ndn.SigConfig, error) {
	return &ndn.SigConfig{
		Type:    ndn.SignatureHmacWithSha256,
		KeyName: enc.Name{enc.Component{Typ: enc.TypeGenericNameComponent, Val: signer.key}},
		Nonce:   signer.timer.Nonce(),
		SigTime: utils.IdPtr(signer.timer.Now()),
		SeqNum:  utils.IdPtr(signer.seq),
	}, nil
}

func (*certIntSigner) EstimateSize() uint {
	return 32
}

func (signer *certIntSigner) ComputeSigValue(covered enc.Wire) ([]byte, error) {
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
	return &certIntSigner{key, timer, 0}
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
