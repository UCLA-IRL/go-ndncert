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
	ChallengeStatusSuccess
)

type InfoResult struct {
	CaPrefix          string
	CaInfo            string
	MaxValidityPeriod uint64
	CaCertificate     []byte
}

type NewResult struct {
	RequestId           RequestId
	AvailableChallenges []string
}

type ChallengeResult struct {
	ChallengeStatus       ChallengeStatus
	RemainingTime         uint64
	RemainingTries        uint64
	IssuedCertificateName enc.Name
}

type requesterState struct {
	caPrefix            string
	caPublicIdentityKey *ecdsa.PublicKey
	certKey             *ecdsa.PrivateKey
	certRequestBytes    []byte
	challengeStatus     ChallengeStatus
	ecdhState           *key_helpers.ECDHState
	interestSigner      ndn.Signer
	ndnEngine           ndn.Engine

	requestId    RequestId
	symmetricKey [16]byte
}

func NewRequesterState(requesterName string, caPrefix string, caPublicIdentityKey *ecdsa.PublicKey, certValidityPeriod uint64, ndnEngine ndn.Engine) (*requesterState, error) {
	logger := log.WithField("module", "requester")
	logger.Infof("Generating a requester state with Requester Name %s and Ca Prefix %s", requesterName, caPrefix)

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
		sec.NewEccSigner(true, false, time.Second*time.Duration(certValidityPeriod), certKey, certName),
	)
	if certRequestError != nil {
		logger.Errorf("Failed to generate the certificate: %s", certRequestError.Error())
		return nil, certRequestError
	}

	return &requesterState{
		caPrefix:            caPrefix,
		caPublicIdentityKey: caPublicIdentityKey,
		certRequestBytes:    certRequest.Join(),
		ecdhState:           &ecdhState,
		certKey:             certKey,
		challengeStatus:     ChallengeStatusBeforeChallenge,
		interestSigner:      sec.NewEccSigner(false, true, time.Duration(0), certKey, certName),
		ndnEngine:           ndnEngine,
	}, nil
}

func ExpressInfoInterest(ndnEngine ndn.Engine, caPrefix string) (*InfoResult, error) {
	logger := log.WithField("module", "requester")
	logger.Infof("Generating an INFO interest to %s", caPrefix+server.PrefixInfo)
	ntSchemaTree := schema.CreateFromJson(server.SchemaJson, map[string]any{})
	infoPrefix, _ := enc.NameFromStr(caPrefix + server.PrefixInfo)
	treeAttachError := ntSchemaTree.Attach(infoPrefix, ndnEngine)
	if treeAttachError != nil {
		logger.Error("NTSchema Tree failed to attach")
		return nil, treeAttachError
	}

	// Fetch the data
	matchedNode := ntSchemaTree.Root().Apply(enc.Matching{})
	callResult := <-matchedNode.Call("NeedChan").(chan schema.NeedResult)
	interestResultError := validateNdnInterestResult(callResult.Status, callResult.NackReason)
	if interestResultError != nil {
		logger.Error("Encountered error validating interest result")
		return nil, interestResultError
	}
	caProfile, parseCaProfileError := ndncert.ParseCaProfile(enc.NewWireReader(callResult.Content), true)
	if parseCaProfileError != nil {
		logger.Error("Encountered error parsing CA Profile")
		return nil, parseCaProfileError
	}
	return &InfoResult{
		CaPrefix:          caProfile.CaPrefix.String(),
		CaInfo:            caProfile.CaInfo,
		MaxValidityPeriod: caProfile.MaxValidPeriod,
		CaCertificate:     caProfile.CaCertificate.Join(),
	}, nil
}

func (requester *requesterState) ExpressNewInterest() (*NewResult, error) {
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
		logger.Error("Encountered error making interest for NEW interest")
		return nil, makeInterestError
	}
	interestConfig := &ndn.InterestConfig{
		CanBePrefix: false,
		MustBeFresh: true,
	}
	ch := make(chan struct{})
	var newResult *NewResult
	expressError := requester.ndnEngine.Express(newInterestFinalName, interestConfig, newInterestWire,
		func(result ndn.InterestResult, data ndn.Data, rawData enc.Wire, sigCovered enc.Wire, nackReason uint64) {
			interestResultError := validateNdnInterestResult(result, &nackReason)
			if interestResultError != nil {
				logger.Errorf("Failed to express interest: %s", interestResultError.Error())
				ch <- struct{}{}
				return
			}
			if !sec.EcdsaValidate(sigCovered, data.Signature(), requester.caPublicIdentityKey) {
				logger.Error("Invalid signature attached to NEW data packet")
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
				newResult = &NewResult{
					RequestId:           requester.requestId,
					AvailableChallenges: newData.Challenge,
				}
			}
			ch <- struct{}{}
		},
	)
	<-ch
	if expressError != nil {
		logger.Error("Failed to express NEW")
		return nil, expressError
	}
	if newResult == nil {
		logger.Error("Error encountered in NEW callback")
		return nil, errors.New("NEW callback error")
	}
	return newResult, nil
}

func (requester *requesterState) ExpressEmailChoiceChallenge(emailAddress string) (*ChallengeResult, error) {
	logger := log.WithField("module", "requester")
	logger.Infof("Generating an email code choice CHALLENGE with email: %s", emailAddress)
	if requester.challengeStatus != ChallengeStatusAfterNewData {
		logger.Error("Bad attempt to generate email choice CHALLENGE: does not follow NEW interest")
		return nil, errors.New("invalid Email Choice Challenge attempted")
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
		logger.Error("Encountered error making interest for email choice CHALLENGE interest")
		return nil, makeInterestError
	}
	interestConfig := &ndn.InterestConfig{
		CanBePrefix: false,
		MustBeFresh: true,
	}
	ch := make(chan struct{})
	var challengeResult *ChallengeResult
	expressError := requester.ndnEngine.Express(challengeInterestFinalName, interestConfig, challengeInterestWire,
		func(result ndn.InterestResult, data ndn.Data, rawData enc.Wire, sigCovered enc.Wire, nackReason uint64) {
			interestResultError := validateNdnInterestResult(result, &nackReason)
			if interestResultError != nil {
				logger.Errorf("Failed to express interest: %s", interestResultError.Error())
				ch <- struct{}{}
				return
			}
			if !sec.EcdsaValidate(sigCovered, data.Signature(), requester.caPublicIdentityKey) {
				logger.Error("Invalid signature attached to email choice CHALLENGE data packet")
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
				logger.Error("Failed email choice CHALLENGE: invalid email")
				logger.Infof("Remaining tries: %d", challengeData.RemainingTries)
				logger.Infof("Remaining time: %d", challengeData.RemainingTime)
			case challengeData.ChallengeStatus == server.ChallengeStatusCodeNeedCode:
				logger.Info("Successfully submitted email choice to server")
				requester.challengeStatus = ChallengeStatusAfterSelectionChallengeData
			}
			challengeResult = &ChallengeResult{
				ChallengeStatus:       requester.challengeStatus,
				RemainingTime:         *challengeData.RemainingTime,
				RemainingTries:        *challengeData.RemainingTries,
				IssuedCertificateName: challengeData.IssuedCertificateName,
			}
			ch <- struct{}{}
		},
	)
	<-ch
	if expressError != nil {
		logger.Error("Failed to express Email Choice Challenge")
		return nil, expressError
	}
	if challengeResult == nil {
		logger.Error("Error encountered in email code CHALLENGE callback")
		return nil, errors.New("email code CHALLENGE callback error ")
	}
	return challengeResult, nil
}

func (requester *requesterState) ExpressEmailCodeChallenge(secretCode string) (*ChallengeResult, error) {
	logger := log.WithField("module", "requester")
	if requester.challengeStatus != ChallengeStatusAfterSelectionChallengeData {
		logger.Error("Bad attempt to generate email code CHALLENGE: does not follow email choice CHALLENGE")
		return nil, errors.New("invalid email code CHALLENGE attempted")
	}
	if len(secretCode) != server.SecretCodeLength {
		logger.Errorf(
			"Bad attempt to generate email code CHALLENGE: secret code does not have length %d", server.SecretCodeLength)
		return nil, fmt.Errorf("incorrect error code length of %d instead of %d", len(secretCode), server.SecretCodeLength)
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
		logger.Error("Encountered error making interest for email code CHALLENGE interest")
		return nil, makeInterestError
	}
	interestConfig := &ndn.InterestConfig{
		CanBePrefix: false,
		MustBeFresh: true,
	}
	ch := make(chan struct{})
	var challengeResult *ChallengeResult
	expressError := requester.ndnEngine.Express(challengeInterestFinalName, interestConfig, challengeInterestWire,
		func(result ndn.InterestResult, data ndn.Data, rawData enc.Wire, sigCovered enc.Wire, nackReason uint64) {
			interestResultError := validateNdnInterestResult(result, &nackReason)
			if interestResultError != nil {
				logger.Errorf("Failed to express interest: %s", interestResultError.Error())
				ch <- struct{}{}
				return
			}
			if !sec.EcdsaValidate(sigCovered, data.Signature(), requester.caPublicIdentityKey) {
				logger.Error("Invalid signature attached to email code CHALLENGE data packet")
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
				logger.Error("Failed email code CHALLENGE: incorrect code")
				logger.Infof("Remaining tries: %d", *challengeData.RemainingTries)
				logger.Infof("Remaining time: %d", *challengeData.RemainingTime)
			case challengeData.ChallengeStatus == server.ChallengeStatusCodeSuccess:
				logger.Infof(
					"Successfully issued certificate with name %s", challengeData.IssuedCertificateName.String())
				requester.challengeStatus = ChallengeStatusSuccess
			}
			remainingTime := 0
			if challengeData.RemainingTime != nil {
				remainingTime = int(*challengeData.RemainingTime)
			}
			remainingTries := 0
			if challengeData.RemainingTries != nil {
				remainingTries = int(*challengeData.RemainingTries)
			}
			challengeResult = &ChallengeResult{
				ChallengeStatus:       requester.challengeStatus,
				RemainingTime:         uint64(remainingTime),
				RemainingTries:        uint64(remainingTries),
				IssuedCertificateName: challengeData.IssuedCertificateName,
			}
			ch <- struct{}{}
		},
	)
	<-ch
	if expressError != nil {
		logger.Error("Failed to express Email Code Challenge")
		return nil, expressError
	}
	if challengeResult == nil {
		logger.Error("Error encountered in email code CHALLENGE callback")
		return nil, errors.New("email code CHALLENGE callback error ")
	}
	return challengeResult, nil
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

func validateNdnInterestResult(result ndn.InterestResult, nackReason *uint64) error {
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
