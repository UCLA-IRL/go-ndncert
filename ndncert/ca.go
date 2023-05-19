package ndncert

import (
	"crypto/rand"
	"crypto/sha256"
	enc "github.com/zjkmxy/go-ndn/pkg/encoding"
	"github.com/zjkmxy/go-ndn/pkg/ndn"
	"github.com/zjkmxy/go-ndn/pkg/ndn/spec_2022"
	"go-ndncert/crypto"
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

func validateName(certName string) ErrorCode {
	nameComponents := strings.Split(certName, "/")
	if len(nameComponents) < minimumCertificateComponentSize {
		// TODO: Add error handling for failure to meet number of certificate components
	}

	if nameComponents[len(nameComponents)+negativeKeyComponentOffset] != keyString {
		// TODO: Add error handling for failure to match keyString correctly
	}
	return NoErrorErrorCode
}

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

func handleEmailChallenge(caState *CaState, challengeInterestPlaintext *ChallengeInterestPlaintext, requestId RequestId) enc.Wire {
	challengeRequestState, _ := caState.ChallengeRequestStateMapping[requestId]
	if challengeRequestState.status == ChallengeStatusNewInterestReceived {
		if len(challengeInterestPlaintext.Parameters) != 1 || challengeInterestPlaintext.Parameters[0].ParameterKey != "" {
			// TODO: Handle the case where Parameters are malformed.
		}

		if challengeRequestState.challengeType != TbdChallengeType {
			// TODO: Handle the case where challenge type
		}

		emailAddress := string(challengeInterestPlaintext.Parameters[0].ParameterValue)
		emailChallengeState, sendEmailStatus := NewEmailChallenge(emailAddress)
		if sendEmailStatus != SendEmailStatusOk {
			// TODO: Handle failed email sending
		}

		challengeRequestState.status = ChallengeStatusChallengeIssued

		remainingTimeUint64 := uint64(emailChallengeState.ChallengeState.Expiry.Second())
		challengeParameters := Parameter{
			ParameterKey:   "",
			ParameterValue: nil,
		}
		challengeDataPlaintext := ChallengeDataPlaintext{
			Status:          ApplicationStatusCodeChallenge,
			ChallengeStatus: ChallengeStatusCodeNeedCode,
			RemainingTries:  &emailChallengeState.ChallengeState.RemainingAttempts,
			RemainingTime:   &remainingTimeUint64,
			Parameters:      ,
		}
	}
}

func OnNew(caState *CaState, interest ndn.Interest, rawInterest enc.Wire, sigCovered enc.Wire, reply ndn.ReplyFunc, deadline time.Time) {
	newInterest, _ := ParseNewInterest(enc.NewWireReader(interest.AppParam()), true)
	certRequestData, _, _ := spec_2022.Spec{}.ReadData(enc.NewBufferReader(newInterest.CertRequest))
	if *certRequestData.ContentType() != ndn.ContentTypeKey {
		// TODO: Handle incorrect content type (not KEY)
	}

	//caPrefixName, _ := enc.NameFromStr(caState.CaPrefix)
	//if !caPrefixName.IsPrefix(certRequestData.Name()) {
	//	// TODO: Handle error if the CA name is not a prefix of the request data name.
	//} // Question - should we even handle this?

	//validateName(certRequestData.Name().String())

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

	if challengeInterestPlaintext.SelectedChallenge == "email" {
		reply(handleEmailChallenge(caState, challengeInterestPlaintext, requestId))
	}
}
