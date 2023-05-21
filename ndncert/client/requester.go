package client

import (
	"errors"
	"fmt"
	enc "github.com/zjkmxy/go-ndn/pkg/encoding"
	"github.com/zjkmxy/go-ndn/pkg/ndn"
	"github.com/zjkmxy/go-ndn/pkg/ndn/spec_2022"
	"github.com/zjkmxy/go-ndn/pkg/security"
	"go-ndncert/crypto"
	"go-ndncert/ndncert"
	"go-ndncert/ndncert/server"
)

const RequestIdLength = 8

type ChallengeStatus uint64
type RequestId [RequestIdLength]byte

const (
	ChallengeStatusBeforeChallenge ChallengeStatus = iota
	ChallengeStatusAfterNewData
	ChallengeStatusAfterSelectionChallengeData
)

type RequesterState struct {
	caPrefix        string
	requestId       RequestId
	symmetricKey    [16]byte
	publicKey       []byte
	ecdhState       *crypto.ECDHState
	ChallengeStatus ChallengeStatus
}

func NewRequesterState(caPrefix string) *RequesterState {
	ecdhState := crypto.ECDHState{}
	ecdhState.GenerateKeyPair()

	return &RequesterState{
		caPrefix:        caPrefix,
		ecdhState:       &ecdhState,
		ChallengeStatus: ChallengeStatusBeforeChallenge,
	}
}

func (requesterState *RequesterState) ExpressNewInterest(ndnEngine ndn.Engine) error {
	newInterestName, _ := enc.NameFromStr(requesterState.caPrefix + "/" + server.PrefixNew)
	newInterestAppParameters := ndncert.NewInterest{
		EcdhPub:     requesterState.ecdhState.PublicKey.Bytes(),
		CertRequest: nil,
	}
	newInterestWire, newInterestFinalName := makeInterestPacket(newInterestName, newInterestAppParameters.Encode())
	interestConfig := &ndn.InterestConfig{
		CanBePrefix: false,
		MustBeFresh: true,
	}
	return ndnEngine.Express(newInterestFinalName, interestConfig, newInterestWire,
		func(result ndn.InterestResult, data ndn.Data, rawData enc.Wire, sigCovered enc.Wire, nackReason uint64) {
			switch requesterState.ChallengeStatus {
			case ChallengeStatusBeforeChallenge:
				newData, _ := ndncert.ParseNewData(enc.NewWireReader(data.Content()), false)
				requesterState.requestId = RequestId(newData.RequestId)
				requesterState.ecdhState.SetRemotePublicKey(newData.EcdhPub)
				sharedSecret := requesterState.ecdhState.GetSharedSecret()
				requesterState.symmetricKey = [16]byte(crypto.HKDF(sharedSecret, newData.Salt))
				requesterState.ChallengeStatus = ChallengeStatusAfterNewData
				return
			}
		},
	)
}

func (requesterState *RequesterState) ExpressEmailChoiceChallenge(ndnEngine ndn.Engine, emailAddress string) error {
	if requesterState.ChallengeStatus != ChallengeStatusAfterNewData {
		return errors.New("invalid Email Choice Challenge attempted")
	}
	challengeInterestName, _ := enc.NameFromStr(requesterState.caPrefix + "/" + server.PrefixChallenge)
	challengeInterestPlaintext := ndncert.ChallengeInterestPlaintext{
		SelectedChallenge: server.SelectedChallengeEmail,
		Parameters: []*ndncert.Parameter{
			{
				ParameterKey:   server.ParameterKeyEmail,
				ParameterValue: []byte(emailAddress),
			},
		},
	}
	encryptedMessage := crypto.EncryptPayload(requesterState.symmetricKey, challengeInterestPlaintext.Encode().Join(), requesterState.requestId)
	challengeInterestAppParameters := ndncert.EncryptedMessage{
		InitializationVector: encryptedMessage.InitializationVector[:],
		AuthenticationTag:    encryptedMessage.AuthenticationTag[:],
		EncryptedPayload:     encryptedMessage.EncryptedPayload,
	}
	challengeInterestWire, challengeInterestFinalName := makeInterestPacket(challengeInterestName, challengeInterestAppParameters.Encode())
	interestConfig := &ndn.InterestConfig{
		CanBePrefix: false,
		MustBeFresh: true,
	}
	return ndnEngine.Express(challengeInterestFinalName, interestConfig, challengeInterestWire,
		func(result ndn.InterestResult, data ndn.Data, rawData enc.Wire, sigCovered enc.Wire, nackReason uint64) {
			encryptedChallengeData, _ := ndncert.ParseEncryptedMessage(enc.NewWireReader(data.Content()), false)
			encryptedMessage := crypto.EncryptedMessage{
				InitializationVector: [12]byte(encryptedChallengeData.InitializationVector),
				AuthenticationTag:    [16]byte(encryptedChallengeData.AuthenticationTag),
				EncryptedPayload:     encryptedChallengeData.EncryptedPayload,
			}
			plaintext := crypto.DecryptPayload(requesterState.symmetricKey, encryptedMessage, requesterState.requestId)
			challengeData, _ := ndncert.ParseChallengeDataPlaintext(enc.NewBufferReader(plaintext), false)
			switch {
			case challengeData.ChallengeStatus == server.ChallengeStatusCodeInvalidEmail:
				// TODO: handle the invalid email case
				return
			case challengeData.ChallengeStatus == server.ChallengeStatusCodeNeedCode:
				requesterState.ChallengeStatus = ChallengeStatusAfterSelectionChallengeData
				return
			}
			return
		},
	)
}

func (requesterState *RequesterState) ExpressEmailCodeChallenge(ndnEngine ndn.Engine, secretCode string) error {
	if requesterState.ChallengeStatus != ChallengeStatusAfterSelectionChallengeData {
		return errors.New("invalid Email Code Challenge attempted")
	}
	if len(secretCode) != server.SecretCodeLength {
		return fmt.Errorf("incorrect error code length of %d instead of %d", len(secretCode), server.SecretCodeLength)
	}
	challengeInterestName, _ := enc.NameFromStr(requesterState.caPrefix + "/" + server.PrefixChallenge)
	challengeInterestPlaintext := ndncert.ChallengeInterestPlaintext{
		SelectedChallenge: server.SelectedChallengeEmail,
		Parameters: []*ndncert.Parameter{
			{
				ParameterKey:   server.ParameterKeyCode,
				ParameterValue: []byte(secretCode),
			},
		},
	}
	encryptedMessage := crypto.EncryptPayload(requesterState.symmetricKey, challengeInterestPlaintext.Encode().Join(), requesterState.requestId)
	challengeInterestAppParameters := ndncert.EncryptedMessage{
		InitializationVector: encryptedMessage.InitializationVector[:],
		AuthenticationTag:    encryptedMessage.AuthenticationTag[:],
		EncryptedPayload:     encryptedMessage.EncryptedPayload,
	}
	challengeInterestWire, challengeInterestFinalName := makeInterestPacket(challengeInterestName, challengeInterestAppParameters.Encode())
	interestConfig := &ndn.InterestConfig{
		CanBePrefix: false,
		MustBeFresh: true,
	}
	return ndnEngine.Express(challengeInterestFinalName, interestConfig, challengeInterestWire,
		func(result ndn.InterestResult, data ndn.Data, rawData enc.Wire, sigCovered enc.Wire, nackReason uint64) {
			encryptedChallengeData, _ := ndncert.ParseEncryptedMessage(enc.NewWireReader(data.Content()), false)
			encryptedMessage := crypto.EncryptedMessage{
				InitializationVector: [12]byte(encryptedChallengeData.InitializationVector),
				AuthenticationTag:    [16]byte(encryptedChallengeData.AuthenticationTag),
				EncryptedPayload:     encryptedChallengeData.EncryptedPayload,
			}
			plaintext := crypto.DecryptPayload(requesterState.symmetricKey, encryptedMessage, requesterState.requestId)
			challengeData, _ := ndncert.ParseChallengeDataPlaintext(enc.NewBufferReader(plaintext), false)
			switch {
			case challengeData.ChallengeStatus == server.ChallengeStatusWrongCode:
				// TODO: handle the case we have an incorrect code
				return
			case challengeData.ChallengeStatus == server.ChallengeStatusCodeSuccess:
				// TODO: handle the case we have a successfully issued certificate
				return
			}
		},
	)
}

func makeInterestPacket(interestName enc.Name, appParameters enc.Wire) (enc.Wire, enc.Name) {
	interestWire, _, finalName, makeInterestError := spec_2022.Spec{}.MakeInterest(
		interestName,
		&ndn.InterestConfig{
			CanBePrefix: false,
			MustBeFresh: true,
		},
		appParameters,
		security.NewSha256Signer())
	if makeInterestError != nil {
		// TODO: Handle error while making interest packet
	}
	return interestWire, finalName
}
