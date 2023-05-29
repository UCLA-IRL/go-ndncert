package client

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	crand "crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/apex/log"
	enc "github.com/zjkmxy/go-ndn/pkg/encoding"
	"github.com/zjkmxy/go-ndn/pkg/ndn"
	"github.com/zjkmxy/go-ndn/pkg/ndn/spec_2022"
	"github.com/zjkmxy/go-ndn/pkg/schema"
	sec "github.com/zjkmxy/go-ndn/pkg/security"
	"github.com/zjkmxy/go-ndn/pkg/utils"
	"go-ndncert/crypto"
	"go-ndncert/ndncert"
	"go-ndncert/ndncert/server"
	mrand "math/rand"
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
	requesterName   string
	caPrefix        string
	ecdhState       *crypto.ECDHState
	certKey         *ecdsa.PrivateKey
	challengeStatus ChallengeStatus

	requestId    RequestId
	symmetricKey [16]byte
}

func NewRequesterState(requesterName string, caPrefix string) *requesterState {
	// TODO: Add implementation for notBefore and notAfter step
	// TODO: Switch to using x.509 certificate format
	logger := log.WithField("module", "requester")
	logger.Infof("Generating a new requester state with Ca Prefix: %s", caPrefix)

	// Generate ECDH Key Pair used for encryption
	ecdhState := crypto.ECDHState{}
	ecdhState.GenerateKeyPair()

	// Generate ECDSA key used for signing
	certKey, certKeyError := ecdsa.GenerateKey(elliptic.P224(), crand.Reader)
	if certKeyError != nil {
		logger.Fatalf("Failed to generate certificate private key using ecdsa")
	}

	return &requesterState{
		requesterName:   requesterName,
		caPrefix:        caPrefix,
		ecdhState:       &ecdhState,
		certKey:         certKey,
		challengeStatus: ChallengeStatusBeforeChallenge,
	}
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
	switch callResult.Status {
	case ndn.InterestResultNack:
		return nil, errors.New(fmt.Sprintf("info failed: nacked with reason %s", *callResult.NackReason))
	case ndn.InterestResultTimeout:
		return nil, errors.New("info failed: interest timed out")
	case ndn.InterestCancelled:
		return nil, errors.New("info failed: interest cancelled")
	}
	fmt.Printf("Received Data: %+v\n", string(callResult.Content.Join()))
	return callResult.Content.Join(), nil
}

func (requesterState *requesterState) ExpressNewInterest(ndnEngine ndn.Engine) error {
	logger := log.WithField(
		"module", "requester",
	)
	logger.Infof("Generating a NEW interest to %s", requesterState.caPrefix+server.PrefixNew)

	// Get the public key encoding
	publicKeyEncoding, publicKeyEncodingError := crypto.EncodePublicKey(&requesterState.certKey.PublicKey)
	if publicKeyEncodingError != nil {
		logger.Fatal("Failed to encode the public key")
	}

	// Generate the cert-request
	keyId := make([]byte, 8)
	issuerId := make([]byte, 8)
	binary.LittleEndian.PutUint64(keyId, mrand.Uint64())
	binary.LittleEndian.PutUint64(issuerId, mrand.Uint64())
	certName, _ := enc.NameFromStr(fmt.Sprintf("%s/KEY/%s/%s/1", requesterState.requesterName, keyId, issuerId))
	certRequest, _, certRequestError := spec_2022.Spec{}.MakeData(
		certName,
		&ndn.DataConfig{
			ContentType:  utils.IdPtr(ndn.ContentTypeKey),
			Freshness:    utils.IdPtr(time.Hour),
			FinalBlockID: nil,
		},
		enc.Wire{publicKeyEncoding},
		sec.NewEccSigner,
	)

	newInterestName, _ := enc.NameFromStr(requesterState.caPrefix + server.PrefixNew)
	newInterestAppParameters := ndncert.NewInterestAppParameters{
		EcdhPub:     requesterState.ecdhState.PublicKey.Bytes(),
		CertRequest: certRequest.Join(),
	}
	newInterestWire, newInterestFinalName := makeInterestPacket(newInterestName, newInterestAppParameters.Encode())
	interestConfig := &ndn.InterestConfig{
		CanBePrefix: false,
		MustBeFresh: true,
	}
	return ndnEngine.Express(newInterestFinalName, interestConfig, newInterestWire,
		func(result ndn.InterestResult, data ndn.Data, rawData enc.Wire, sigCovered enc.Wire, nackReason uint64) {
			switch requesterState.challengeStatus {
			case ChallengeStatusBeforeChallenge:
				newData, _ := ndncert.ParseNewData(enc.NewWireReader(data.Content()), true)
				requesterState.requestId = RequestId(newData.RequestId)
				requesterState.ecdhState.SetRemotePublicKey(newData.EcdhPub)
				sharedSecret := requesterState.ecdhState.GetSharedSecret()
				requesterState.symmetricKey = [16]byte(crypto.HKDF(sharedSecret, newData.Salt))
				requesterState.challengeStatus = ChallengeStatusAfterNewData
				return
			}
		},
	)
}

func (requesterState *requesterState) ExpressEmailChoiceChallenge(ndnEngine ndn.Engine, emailAddress string) error {
	logger := log.WithField("module", "requester")
	if requesterState.challengeStatus != ChallengeStatusAfterNewData {
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
				requesterState.challengeStatus = ChallengeStatusAfterSelectionChallengeData
				return
			}
			return
		},
	)
}

func (requesterState *requesterState) ExpressEmailCodeChallenge(ndnEngine ndn.Engine, secretCode string) error {
	logger := log.WithField("module", "requester")
	if requesterState.challengeStatus != ChallengeStatusAfterSelectionChallengeData {
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
		sec.NewSha256Signer())
	if makeInterestError != nil {
		log.WithField("module", "requester").Fatalf("Failed to make interest packet")
	}
	return interestWire, finalName
}
