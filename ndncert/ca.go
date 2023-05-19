package ndncert

import (
	"crypto/rand"
	"crypto/sha256"
	"github.com/dchest/uniuri"
	enc "github.com/zjkmxy/go-ndn/pkg/encoding"
	"github.com/zjkmxy/go-ndn/pkg/ndn"
	"github.com/zjkmxy/go-ndn/pkg/ndn/spec_2022"
	"go-ndncert/crypto"
	"go-ndncert/email"
	"go.step.sm/crypto/randutil"
	"golang.org/x/exp/slices"
	"strings"
	"time"
)

const RequestIdLength = 8

type ApplicationStatusCode uint64
type ChallengeStatus uint64
type ChallengeType uint64
type ErrorCode uint64
type ErrorReason []byte
type RequestId [RequestIdLength]byte

const (
	ApplicationStatusCodeBeforeChallenge ApplicationStatusCode = 0
	ApplicationStatusCodeChallenge                             = 1
	ApplicationStatusCodePending                               = 2
	ApplicationStatusCodeSuccess                               = 3
	ApplicationStatusCodeFailure                               = 4
)

const (
	ChallengeStatusCodeNeedCode     string = "need-code"
	ChallengeStatusCodeInvalidEmail        = "invalid-email"
	ChallengeStatusCodeSuccess             = "success"
)

const (
	ChallengeStatusNewInterestReceived ChallengeStatus = iota
	ChallengeStatusChallengeIssued
	//ChallengeStatusChallengeInterestReceived
)

const (
	TbdChallengeType ChallengeType = iota
	EmailChallengeType
)

const (
	NoErrorErrorCode            ErrorCode = 0
	BadInterestFormatErrorCode            = 1
	BadParameterFormatErrorCode           = 2
	BadSignatureErrorCode                 = 3
	InvalidParametersErrorCode            = 4
	NameNotAllowedErrorCode               = 5
	BadValidityPeriodErrorCode            = 6
	RunOutOfTriesErrorCode                = 7
	RunOutOfTimeErrorCode                 = 8
	// NoAvailableNamesErrorCode             = 9 // Currently unused (no support for PROBE)
)

const (
	BadInterestFormatErrorReason  string = "Bad Interest Format: the Interest format is incorrect, e.g., no ApplicationParameters."
	BadParameterFormatErrorReason        = "Bad Parameter Format: the ApplicationParameters field is not correctly formed."
	BadSignatureErrorReason              = "Bad Signature or signature info: the Interest carries an invalid signature."
	InvalidParametersErrorReason         = "Invalid parameters: the input from the requester is not expected."
	NameNotAllowedErrorReason            = "Name not allowed: the requested certificate name cannot be assigned to the requester."
	BadValidityPeriodErrorReason         = "Bad ValidityPeriod: requested certificate has an erroneous validity period, e.g., too long time."
	RunOutOfTriesErrorReason             = "Run out of tries: the requester failed to complete the challenge within allowed number of attempts."
	RunOutOfTimeErrorReason              = "Run out of time: the requester failed to complete the challenge within time limit."
	// NoAvailableNamesErrorReason          = "No Available Names: the CA finds there is no namespaces available based on the PROBE parameters provided." // Currently unused (no support for PROBE)
)

var AvailableChallenges = []string{"email"}

type ChallengeRequestState struct {
	requestId       RequestId
	status          ChallengeStatus
	encryptionKey   [16]byte
	encryptionIv    []byte
	decryptionIv    []byte
	challengeType   ChallengeType
	challengeState  *EmailChallengeState
	clientPublicKey []byte
}

type CaState struct {
	CaCert                enc.Buffer
	CaInfo                string
	CaPrefix              string
	MaxCertValidityPeriod time.Duration

	ChallengeRequestStateMapping map[RequestId]*ChallengeRequestState
}

const minimumCertificateComponentSize = 4
const negativeKeyComponentOffset = -4
const keyString = "KEY"
const negativeRequestIdOffset = -2

func getEcdhState(newInterest *NewInterest) crypto.ECDHState {
	ecdhState := crypto.ECDHState{}
	ecdhState.GenerateKeyPair()
	ecdhState.SetRemotePublicKey(newInterest.EcdhPub)

	return ecdhState
}

func getSalt() []byte {
	salt := make([]byte, sha256.New().Size())
	rand.Read(salt)

	return salt
}

func getRequestId(caState *CaState) RequestId {
	randomRequestId, _ := randutil.Alphanumeric(RequestIdLength)
	requestId := (RequestId)([]byte(randomRequestId))
	if _, ok := caState.ChallengeRequestStateMapping[requestId]; ok {
		return getRequestId(caState)
	}
	return requestId
}

func generateCertificateName(caState *CaState) enc.Name {
	// Generate random certificate name by taking ca prefix and appending a 16-long string
	certificateName, _ := enc.NameFromStr(caState.CaPrefix + "/" + uniuri.New())
	return certificateName
}

func OnNew(caState *CaState, interest ndn.Interest, rawInterest enc.Wire, sigCovered enc.Wire, reply ndn.ReplyFunc, deadline time.Time) {
	newInterest, _ := ParseNewInterest(enc.NewWireReader(interest.AppParam()), true)
	certRequestData, _, _ := spec_2022.Spec{}.ReadData(enc.NewBufferReader(newInterest.CertRequest))
	if *certRequestData.ContentType() != ndn.ContentTypeKey {
		// TODO: Handle incorrect content type (not KEY)
	}

	ecdhState := getEcdhState(newInterest)
	salt := getSalt()
	requestId := getRequestId(caState)

	caState.ChallengeRequestStateMapping[requestId] = &ChallengeRequestState{
		requestId:       requestId,
		status:          ChallengeStatusNewInterestReceived,
		encryptionKey:   ([16]byte)(crypto.HKDF(ecdhState.GetSharedSecret(), salt)),
		encryptionIv:    nil,
		decryptionIv:    nil,
		challengeType:   TbdChallengeType,
		challengeState:  nil,
		clientPublicKey: certRequestData.Content().Join(),
	}

	newData := NewData{
		EcdhPub:   ecdhState.PublicKey.Bytes(),
		Salt:      salt,
		RequestId: requestId[:],
		Challenge: AvailableChallenges,
	}

	newDataWire := newData.Encode()
	reply(newDataWire)
}

func OnChallenge(caState *CaState, interest ndn.Interest, rawInterest enc.Wire, sigCovered enc.Wire, reply ndn.ReplyFunc, deadline time.Time) {
	nameComponents := strings.Split(interest.Name().String(), "/")
	if len(nameComponents[len(nameComponents)+negativeRequestIdOffset]) != RequestIdLength {
		// TODO: Handle Request ID Length mismatch.
	}

	requestId := (RequestId)([]byte(nameComponents[len(nameComponents)+negativeRequestIdOffset]))
	encryptedMessageReader := enc.NewWireReader(interest.AppParam())
	encryptedMessage, _ := ParseEncryptedMessage(encryptedMessageReader, true)
	initializationVector := ([crypto.NonceSizeBytes]byte)(encryptedMessage.InitializationVector)
	authenticationTag := ([crypto.TagSizeBytes]byte)(encryptedMessage.AuthenticationTag)
	encryptedMessageObject := crypto.EncryptedMessage{
		InitializationVector: initializationVector,
		AuthenticationTag:    authenticationTag,
		EncryptedPayload:     encryptedMessage.EncryptedPayload,
	}
	challengeRequestState, ok := caState.ChallengeRequestStateMapping[requestId]
	if !ok {
		// TODO: Handle the case where we do not have matching request id from NEW
	}

	plaintext := crypto.DecryptPayload(challengeRequestState.encryptionKey, encryptedMessageObject, requestId)
	challengeInterestPlaintext, _ := ParseChallengeInterestPlaintext(enc.NewBufferReader(plaintext), true)

	if !slices.Contains(AvailableChallenges, challengeInterestPlaintext.SelectedChallenge) {
		// TODO: Handle the case where available challenge is not supported
	}

	switch {
	case challengeInterestPlaintext.SelectedChallenge == "email":
		switch challengeRequestState.status {
		case ChallengeStatusNewInterestReceived:
			if len(challengeInterestPlaintext.Parameters) != 1 || challengeInterestPlaintext.Parameters[0].ParameterKey != "email" {
				// TODO: Handle the case where Parameters are malformed.
			}

			emailAddress := string(challengeInterestPlaintext.Parameters[0].ParameterValue)
			emailChallengeState, sendEmailStatus := NewEmailChallenge(emailAddress)
			if sendEmailStatus != email.StatusSuccess {
				// TODO: Handle failed email sending
				challengeRequestState.challengeState.ChallengeState.RemainingAttempts -= 1

			} else {
				challengeRequestState.status = ChallengeStatusChallengeIssued
				remainingTimeUint64 := uint64(emailChallengeState.ChallengeState.Expiry.Second())
				plaintextChallenge := ChallengeDataPlaintext{
					Status:          ApplicationStatusCodeChallenge,
					ChallengeStatus: ChallengeStatusCodeNeedCode,
					RemainingTries:  &emailChallengeState.ChallengeState.RemainingAttempts,
					RemainingTime:   &remainingTimeUint64,
				}
				encryptedChallenge := crypto.EncryptPayload(challengeRequestState.encryptionKey, plaintextChallenge.Encode().Join(), requestId)
				challengeEncryptedMessage := EncryptedMessage{
					InitializationVector: encryptedChallenge.InitializationVector[:],
					AuthenticationTag:    encryptedChallenge.AuthenticationTag[:],
					EncryptedPayload:     encryptedChallenge.EncryptedPayload,
				}

				challengeRequestState.challengeState = emailChallengeState
				reply(challengeEncryptedMessage.Encode())
			}
		case ChallengeStatusChallengeIssued:
			if len(challengeInterestPlaintext.Parameters) != 1 || challengeInterestPlaintext.Parameters[0].ParameterKey != "code" {
				// TODO: Handle the case where Parameters are malformed.
			}
			if challengeRequestState.challengeState.ChallengeState.Expiry.After(time.Now()) {
				// TODO: Handle the case where the user runs out of time.
			}
			secretCode := string(challengeInterestPlaintext.Parameters[0].ParameterValue)
			if secretCode != challengeRequestState.challengeState.SecretCode {
				// TODO: Handle the case where the secret code is incorrect.
				challengeRequestState.challengeState.ChallengeState.RemainingAttempts -= 1
			} else {
				plaintextSuccess := ChallengeDataPlaintext{
					Status:                ApplicationStatusCodeSuccess,
					ChallengeStatus:       ChallengeStatusCodeSuccess,
					IssuedCertificateName: generateCertificateName(caState),
				}
				encryptedSuccess := crypto.EncryptPayload(challengeRequestState.encryptionKey, plaintextSuccess.Encode().Join(), requestId)
				successEncryptedMessage := EncryptedMessage{
					InitializationVector: encryptedSuccess.InitializationVector[:],
					AuthenticationTag:    encryptedSuccess.AuthenticationTag[:],
					EncryptedPayload:     encryptedSuccess.EncryptedPayload,
				}
				reply(successEncryptedMessage.Encode())
				delete(caState.ChallengeRequestStateMapping, requestId)
			}
		}
	}
}
