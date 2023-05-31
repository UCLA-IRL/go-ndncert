package client

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	crand "crypto/rand"
	"errors"
	"fmt"
	"github.com/apex/log"
	"github.com/dchest/uniuri"
	enc "github.com/zjkmxy/go-ndn/pkg/encoding"
	"github.com/zjkmxy/go-ndn/pkg/ndn"
	"github.com/zjkmxy/go-ndn/pkg/ndn/spec_2022"
	"github.com/zjkmxy/go-ndn/pkg/schema"
	sec "github.com/zjkmxy/go-ndn/pkg/security"
	"github.com/zjkmxy/go-ndn/pkg/utils"
	"go-ndncert/key_helpers"
	"go-ndncert/ndncert"
	"go-ndncert/ndncert/server"
	"time"
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

type requesterState struct {
	caPrefix         string
	certKey          *ecdsa.PrivateKey
	certRequestBytes []byte
	challengeStatus  ChallengeStatus
	ecdhState        *key_helpers.ECDHState
	interestSigner   ndn.Signer
	ndnEngine        ndn.Engine

	requestId    RequestId
	symmetricKey [16]byte
}

func NewRequesterState(requesterName string, caPrefix string, ndnEngine ndn.Engine, ndnTimer ndn.Timer) (*requesterState, error) {
	logger := log.WithField("module", "requester")
	logger.Infof("Generating a new requester state with Requester Name %s and Ca Prefix %s", requesterName, caPrefix)

	// Generate ECDH Key Pair used for encryption
	ecdhState := key_helpers.ECDHState{}
	ecdhState.GenerateKeyPair()

	// Generate ECDSA key used for signing
	certKey, certKeyError := ecdsa.GenerateKey(elliptic.P256(), crand.Reader)
	if certKeyError != nil {
		logger.Error("Failed to generate certificate private key using ecdsa")
		return nil, certKeyError
	}

	// Get the public key encoding
	publicKeyEncoding, publicKeyEncodingError := key_helpers.EncodePublicKey(&certKey.PublicKey)
	if publicKeyEncodingError != nil {
		logger.Error("Failed to encode the public key")
		return nil, publicKeyEncodingError
	}

	// Generate the cert-request
	logger.Infof("Generating public key %+v", certKey.PublicKey)
	keyId := uniuri.NewLen(8)
	issuerId := uniuri.NewLen(8)
	logger.Infof("Key ID: %s, Issuer ID: %s", keyId, issuerId)
	certName, _ := enc.NameFromStr(fmt.Sprintf("%s/KEY/%s/%s/1", requesterName, keyId, issuerId))
	certRequest, _, certRequestError := spec_2022.Spec{}.MakeData(
		certName,
		&ndn.DataConfig{
			ContentType:  utils.IdPtr(ndn.ContentTypeKey),
			Freshness:    utils.IdPtr(time.Hour),
			FinalBlockID: nil,
		},
		enc.Wire{publicKeyEncoding},
		sec.NewEccSigner(true, false, time.Hour*12, certKey, certName),
	)
	if certRequestError != nil {
		logger.Errorf("Failed to generate the certificate: %s", certRequestError.Error())
		return nil, certRequestError
	}

	return &requesterState{
		caPrefix:         caPrefix,
		certRequestBytes: certRequest.Join(),
		ecdhState:        &ecdhState,
		certKey:          certKey,
		challengeStatus:  ChallengeStatusBeforeChallenge,
		interestSigner:   sec.NewEccSigner(false, true, time.Duration(0), certKey, certName),
		ndnEngine:        ndnEngine,
	}, nil
}

func ExpressInfoInterest(ndnEngine ndn.Engine, caPrefix string) ([]byte, error) {
	logger := log.WithField("module", "requester")
	logger.Infof("Generating an INFO interest to %s", caPrefix+server.PrefixInfo)
	ntSchemaTree := schema.CreateFromJson(server.SchemaJson, map[string]any{})
	infoPrefix, _ := enc.NameFromStr(caPrefix + server.PrefixInfo)
	treeAttachError := ntSchemaTree.Attach(infoPrefix, ndnEngine)
	if treeAttachError != nil {
		logger.Error("NTSchema Tree failed to attach")
		return nil, treeAttachError
	}
	defer ntSchemaTree.Detach()

	// Fetch the data
	matchedNode := ntSchemaTree.Root().Apply(enc.Matching{})
	callResult := <-matchedNode.Call("NeedChan").(chan schema.NeedResult)
	interestResultError := validateNdnInterestResult(callResult.Status, *callResult.NackReason)
	if interestResultError != nil {
		return nil, interestResultError
	}
	return callResult.Content.Join(), nil
}

func (requester *requesterState) ExpressNewInterest(certificateValidityPeriod time.Duration) error {
	logger := log.WithField(
		"module", "requester",
	)
	logger.Infof("Generating a NEW interest to %s", requester.caPrefix+server.PrefixNew)

	newInterestName, _ := enc.NameFromStr(requester.caPrefix + server.PrefixNew)
	newInterestAppParameters := ndncert.NewInterestAppParameters{
		EcdhPub:     requester.ecdhState.PublicKey.Bytes(),
		CertRequest: requester.certRequestBytes,
	}
	newInterestWire, newInterestFinalName, makeInterestError := makeInterestPacket(newInterestName, newInterestAppParameters.Encode(), requester.interestSigner)
	if makeInterestError != nil {
		logger.Error("Encountered error making interest for new interest")
		return makeInterestError
	}
	interestConfig := &ndn.InterestConfig{
		CanBePrefix: false,
		MustBeFresh: true,
	}
	ch := make(chan struct{})
	expressError := requester.ndnEngine.Express(newInterestFinalName, interestConfig, newInterestWire,
		func(result ndn.InterestResult, data ndn.Data, rawData enc.Wire, sigCovered enc.Wire, nackReason uint64) {
			interestResultError := validateNdnInterestResult(result, nackReason)
			if interestResultError != nil {
				logger.Errorf("Failed to express interest: %s", interestResultError.Error())
				ch <- struct{}{}
				return
			}
			switch requester.challengeStatus {
			case ChallengeStatusBeforeChallenge:
				newData, _ := ndncert.ParseNewData(enc.NewWireReader(data.Content()), true)
				requester.requestId = RequestId(newData.RequestId)
				requester.ecdhState.SetRemotePublicKey(newData.EcdhPub)
				sharedSecret := requester.ecdhState.GetSharedSecret()
				requester.symmetricKey = [16]byte(key_helpers.HKDF(sharedSecret, newData.Salt))
				requester.challengeStatus = ChallengeStatusAfterNewData
			}
			ch <- struct{}{}
		},
	)
	if expressError != nil {
		logger.Error("Failed to express Email Choice Challenge")
		return expressError
	}
	<-ch
	return nil
}

func (requester *requesterState) ExpressEmailChoiceChallenge(emailAddress string) error {
	logger := log.WithField("module", "requester")
	logger.Infof("Generating an email code choice challenge with email: %s", emailAddress)
	if requester.challengeStatus != ChallengeStatusAfterNewData {
		logger.Error("Bad attempt to generate email choice challenge: does not follow NEW interest")
		return errors.New("invalid Email Choice Challenge attempted")
	}
	emailParameters := map[string][]byte{
		server.SelectedChallengeEmail: []byte(emailAddress),
	}
	challengeInterestName, _ := enc.NameFromStr(requester.caPrefix + server.PrefixChallenge + "/" + string(requester.requestId[:]))
	challengeInterestPlaintext := ndncert.ChallengeInterestPlaintext{
		SelectedChallenge: server.SelectedChallengeEmail,
		Parameters:        emailParameters,
	}
	encryptedMessage := key_helpers.EncryptPayload(requester.symmetricKey, challengeInterestPlaintext.Encode().Join(), requester.requestId)
	challengeInterestAppParameters := ndncert.EncryptedMessage{
		InitializationVector: encryptedMessage.InitializationVector[:],
		AuthenticationTag:    encryptedMessage.AuthenticationTag[:],
		EncryptedPayload:     encryptedMessage.EncryptedPayload,
	}
	challengeInterestWire, challengeInterestFinalName, makeInterestError := makeInterestPacket(challengeInterestName, challengeInterestAppParameters.Encode(), requester.interestSigner)
	if makeInterestError != nil {
		logger.Error("Encountered error making interest for email choice challenge interest")
		return makeInterestError
	}
	interestConfig := &ndn.InterestConfig{
		CanBePrefix: false,
		MustBeFresh: true,
	}
	ch := make(chan struct{})
	expressError := requester.ndnEngine.Express(challengeInterestFinalName, interestConfig, challengeInterestWire,
		func(result ndn.InterestResult, data ndn.Data, rawData enc.Wire, sigCovered enc.Wire, nackReason uint64) {
			interestResultError := validateNdnInterestResult(result, nackReason)
			if interestResultError != nil {
				logger.Errorf("Failed to express interest: %s", interestResultError.Error())
				ch <- struct{}{}
				return
			}
			encryptedChallengeData, _ := ndncert.ParseEncryptedMessage(enc.NewWireReader(data.Content()), true)
			encryptedMessage := key_helpers.EncryptedMessage{
				InitializationVector: [12]byte(encryptedChallengeData.InitializationVector),
				AuthenticationTag:    [16]byte(encryptedChallengeData.AuthenticationTag),
				EncryptedPayload:     encryptedChallengeData.EncryptedPayload,
			}
			plaintext := key_helpers.DecryptPayload(requester.symmetricKey, encryptedMessage, requester.requestId)
			challengeData, _ := ndncert.ParseChallengeDataPlaintext(enc.NewBufferReader(plaintext), true)
			switch {
			case challengeData.ChallengeStatus == server.ChallengeStatusCodeInvalidEmail:
				logger.Error("Failed email choice challenge: invalid email")
				logger.Infof("Remaining tries: %d", challengeData.RemainingTries)
				logger.Infof("Remaining time: %d", challengeData.RemainingTime)
			case challengeData.ChallengeStatus == server.ChallengeStatusCodeNeedCode:
				logger.Info("Successfully submitted email choice to server")
				requester.challengeStatus = ChallengeStatusAfterSelectionChallengeData
			}
			ch <- struct{}{}
		},
	)
	if expressError != nil {
		logger.Error("Failed to express Email Choice Challenge")
		return expressError
	}
	<-ch
	return nil
}

func (requester *requesterState) ExpressEmailCodeChallenge(secretCode string) error {
	logger := log.WithField("module", "requester")
	if requester.challengeStatus != ChallengeStatusAfterSelectionChallengeData {
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
	challengeInterestName, _ := enc.NameFromStr(requester.caPrefix + server.PrefixChallenge + "/" + string(requester.requestId[:]))
	challengeInterestPlaintext := ndncert.ChallengeInterestPlaintext{
		SelectedChallenge: server.SelectedChallengeEmail,
		Parameters:        secretCodeParameters,
	}
	encryptedMessage := key_helpers.EncryptPayload(requester.symmetricKey, challengeInterestPlaintext.Encode().Join(), requester.requestId)
	challengeInterestAppParameters := ndncert.EncryptedMessage{
		InitializationVector: encryptedMessage.InitializationVector[:],
		AuthenticationTag:    encryptedMessage.AuthenticationTag[:],
		EncryptedPayload:     encryptedMessage.EncryptedPayload,
	}
	challengeInterestWire, challengeInterestFinalName, makeInterestError := makeInterestPacket(challengeInterestName, challengeInterestAppParameters.Encode(), requester.interestSigner)
	if makeInterestError != nil {
		logger.Error("Encountered error making interest for email code challenge interest")
		return makeInterestError
	}
	interestConfig := &ndn.InterestConfig{
		CanBePrefix: false,
		MustBeFresh: true,
	}
	ch := make(chan struct{})
	expressError := requester.ndnEngine.Express(challengeInterestFinalName, interestConfig, challengeInterestWire,
		func(result ndn.InterestResult, data ndn.Data, rawData enc.Wire, sigCovered enc.Wire, nackReason uint64) {
			interestResultError := validateNdnInterestResult(result, nackReason)
			if interestResultError != nil {
				logger.Errorf("Failed to express interest: %s", interestResultError.Error())
				ch <- struct{}{}
				return
			}
			encryptedChallengeData, _ := ndncert.ParseEncryptedMessage(enc.NewWireReader(data.Content()), true)
			encryptedMessage := key_helpers.EncryptedMessage{
				InitializationVector: [12]byte(encryptedChallengeData.InitializationVector),
				AuthenticationTag:    [16]byte(encryptedChallengeData.AuthenticationTag),
				EncryptedPayload:     encryptedChallengeData.EncryptedPayload,
			}
			plaintext := key_helpers.DecryptPayload(requester.symmetricKey, encryptedMessage, requester.requestId)
			challengeData, _ := ndncert.ParseChallengeDataPlaintext(enc.NewBufferReader(plaintext), true)
			switch {
			case challengeData.ChallengeStatus == server.ChallengeStatusWrongCode:
				logger.Error("Failed email code challenge: incorrect code")
				logger.Infof("Remaining tries: %d", challengeData.RemainingTries)
				logger.Infof("Remaining time: %d", challengeData.RemainingTime)
			case challengeData.ChallengeStatus == server.ChallengeStatusCodeSuccess:
				logger.Infof(
					"Successfully issued certificate with name %s", challengeData.IssuedCertificateName.String())
			}
			ch <- struct{}{}
		},
	)
	if expressError != nil {
		logger.Error("Failed to express Email Code Challenge")
		return expressError
	}
	<-ch
	return nil
}

func makeInterestPacket(interestName enc.Name, appParameters enc.Wire, ndnSigner ndn.Signer) (enc.Wire, enc.Name, error) {
	interestWire, _, finalName, makeInterestError := spec_2022.Spec{}.MakeInterest(
		interestName,
		&ndn.InterestConfig{
			CanBePrefix: false,
			MustBeFresh: true,
		},
		appParameters,
		ndnSigner)
	if makeInterestError != nil {
		return nil, nil, makeInterestError
	}
	return interestWire, finalName, nil
}

func validateNdnInterestResult(result ndn.InterestResult, nackReason uint64) error {
	switch result {
	case ndn.InterestResultNack:
		return errors.New(fmt.Sprintf("info failed: nacked with reason %d", nackReason))
	case ndn.InterestResultTimeout:
		return errors.New("info failed: interest timed out")
	case ndn.InterestCancelled:
		return errors.New("info failed: interest cancelled")
	}
	return nil
}
