package client

import (
	"errors"
	"fmt"
	"github.com/apex/log"
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
	ChallengeStatusFailure
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
	log.WithField(
		"module", "requester",
	).Infof("Generating a new requester state with Ca Prefix: %s", caPrefix)

	ecdhState := crypto.ECDHState{}
	ecdhState.GenerateKeyPair()
	return &RequesterState{
		caPrefix:        caPrefix,
		ecdhState:       &ecdhState,
		ChallengeStatus: ChallengeStatusBeforeChallenge,
	}
}

func (requesterState *RequesterState) ExpressNewInterest(ndnEngine ndn.Engine) error {
	log.WithField(
		"module", "requester",
	).Infof("Generating a NEW interest to %s", requesterState.caPrefix+server.PrefixNew)

	newInterestName, _ := enc.NameFromStr(requesterState.caPrefix + server.PrefixNew)
	newInterestAppParameters := ndncert.NewInterestAppParameters{
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
				newData, _ := ndncert.ParseNewData(enc.NewWireReader(data.Content()), true)
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
	logger := log.WithField("module", "requester")
	if requesterState.ChallengeStatus != ChallengeStatusAfterNewData {
		logger.Error("Bad attempt to generate email choice challenge: does not follow NEW interest")
		return errors.New("invalid Email Choice Challenge attempted")
	}
	emailParameters := map[string][]byte{
		server.SelectedChallengeEmail: []byte(emailAddress),
	}
	challengeInterestName, _ := enc.NameFromStr(requesterState.caPrefix + server.PrefixChallenge)
	challengeInterestPlaintext := ndncert.ChallengeInterestPlaintext{
		SelectedChallenge: server.SelectedChallengeEmail,
		Parameters:        emailParameters,
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
			encryptedChallengeData, _ := ndncert.ParseEncryptedMessage(enc.NewWireReader(data.Content()), true)
			encryptedMessage := crypto.EncryptedMessage{
				InitializationVector: [12]byte(encryptedChallengeData.InitializationVector),
				AuthenticationTag:    [16]byte(encryptedChallengeData.AuthenticationTag),
				EncryptedPayload:     encryptedChallengeData.EncryptedPayload,
			}
			plaintext := crypto.DecryptPayload(requesterState.symmetricKey, encryptedMessage, requesterState.requestId)
			challengeData, _ := ndncert.ParseChallengeDataPlaintext(enc.NewBufferReader(plaintext), true)
			switch {
			case challengeData.ChallengeStatus == server.ChallengeStatusCodeInvalidEmail:
				logger.Error("Failed email choice challenge: invalid email")
				logger.Infof("Remaining tries: %d", challengeData.RemainingTries)
				logger.Infof("Remaining time: %d", challengeData.RemainingTime)
				return
			case challengeData.ChallengeStatus == server.ChallengeStatusCodeNeedCode:
				logger.Info("Successfully submitted email choice to server")
				requesterState.ChallengeStatus = ChallengeStatusAfterSelectionChallengeData
				return
			}
			return
		},
	)
}

func (requesterState *RequesterState) ExpressEmailCodeChallenge(ndnEngine ndn.Engine, secretCode string) error {
	logger := log.WithField("module", "requester")
	if requesterState.ChallengeStatus != ChallengeStatusAfterSelectionChallengeData {
		logger.Error("Bad attempt to generate email code challenge: does not follow email choice challenge")
		return errors.New("invalid Email Code Challenge attempted")
	}
	if len(secretCode) != server.SecretCodeLength {
		logger.Errorf(
			"Bad attempt to generate email code challenge: secret code does not have length %d", server.SecretCodeLength)
		return fmt.Errorf("incorrect error code length of %d instead of %d", len(secretCode), server.SecretCodeLength)
	}
	secretCodeParameters := map[string][]byte{
		server.ParameterKeyCode: []byte(secretCode),
	}
	challengeInterestName, _ := enc.NameFromStr(requesterState.caPrefix + server.PrefixChallenge)
	challengeInterestPlaintext := ndncert.ChallengeInterestPlaintext{
		SelectedChallenge: server.SelectedChallengeEmail,
		Parameters:        secretCodeParameters,
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
			encryptedChallengeData, _ := ndncert.ParseEncryptedMessage(enc.NewWireReader(data.Content()), true)
			encryptedMessage := crypto.EncryptedMessage{
				InitializationVector: [12]byte(encryptedChallengeData.InitializationVector),
				AuthenticationTag:    [16]byte(encryptedChallengeData.AuthenticationTag),
				EncryptedPayload:     encryptedChallengeData.EncryptedPayload,
			}
			plaintext := crypto.DecryptPayload(requesterState.symmetricKey, encryptedMessage, requesterState.requestId)
			challengeData, _ := ndncert.ParseChallengeDataPlaintext(enc.NewBufferReader(plaintext), true)
			switch {
			case challengeData.ChallengeStatus == server.ChallengeStatusWrongCode:
				logger.Error("Failed email code challenge: incorrect code")
				logger.Infof("Remaining tries: %d", challengeData.RemainingTries)
				logger.Infof("Remaining time: %d", challengeData.RemainingTime)
				return
			case challengeData.ChallengeStatus == server.ChallengeStatusCodeSuccess:
				logger.Infof(
					"Successfully issued certificate with name %s", challengeData.IssuedCertificateName.String())
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
		log.WithField("module", "requester").Fatalf("Failed to make interest packet")
	}
	return interestWire, finalName
}
