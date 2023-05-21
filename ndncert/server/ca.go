package server

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"github.com/dchest/uniuri"
	enc "github.com/zjkmxy/go-ndn/pkg/encoding"
	"github.com/zjkmxy/go-ndn/pkg/ndn"
	"github.com/zjkmxy/go-ndn/pkg/ndn/spec_2022"
	"github.com/zjkmxy/go-ndn/pkg/schema"
	sec "github.com/zjkmxy/go-ndn/pkg/security"
	"github.com/zjkmxy/go-ndn/pkg/utils"
	"go-ndncert/crypto"
	"go-ndncert/email"
	"go-ndncert/ndncert"
	"go.step.sm/crypto/randutil"
	"golang.org/x/exp/slices"
	"gopkg.in/yaml.v3"
	"os"
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
	PrefixInfo      string = "/CA/INFO"
	PrefixNew              = "/CA/NEW"
	PrefixChallenge        = "/CA/CHALLENGE"
)

const SchemaJson = `{
  "nodes": {
    "/": {
      "type": "RdrNode",
      "attrs": {
        "MetaFreshness": 10,
        "MaxRetriesForMeta": 2,
        "MetaLifetime": 6000,
        "Lifetime": 6000,
        "Freshness": 3153600000000,
        "ValidDuration": 3153600000000,
        "SegmentSize": 80,
        "MaxRetriesOnFailure": 3,
        "Pipeline": "SinglePacket"
      }
    }
  },
  "policies": [
    {
      "type": "Sha256Signer",
      "path": "/32=metadata/<v=versionNumber>/seg=0"
    },
    {
      "type": "Sha256Signer",
      "path": "/32=metadata"
    },
    {
      "type": "Sha256Signer",
      "path": "/<v=versionNumber>/<seg=segmentNumber>"
    },
    {
      "type": "MemStorage",
      "path": "/",
      "attrs": {}
    }
  ]
}`

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
	ChallengeStatusWrongCode               = "wrong-code"
	ChallengeStatusCodeSuccess             = "success"
)

const (
	SelectedChallengeEmail string = "email"
)

const (
	ParameterKeyEmail string = "email"
	ParameterKeyCode         = "code"
)

const (
	ChallengeStatusNewInterestReceived ChallengeStatus = iota
	ChallengeStatusChallengeIssued
	// ChallengeStatusChallengeInterestReceived
)

const (
	TbdChallengeType ChallengeType = iota
	EmailChallengeType
)

const (
	ErrorCodeBadInterestFormat ErrorCode = 1
	ErrorCodeBadParameter                = 2
	ErrorCodeBadSignature                = 3
	ErrorCodeInvalidParameters           = 4
	ErrorCodeNameNotAllowed              = 5
	ErrorCodeBadValidityPeriod           = 6
	ErrorCodeRunOutOfTries               = 7
	ErrorCodeRunOutOfTime                = 8
	// ErrorCodeNoAvailableNames             = 9 // Currently unused (no support for PROBE)
)

const (
	ErrorReasonBadInterestFormat  string = "Bad Interest Format: the Interest format is incorrect, e.g., no ApplicationParameters."
	ErrorReasonBadParameterFormat        = "Bad Parameter Format: the ApplicationParameters field is not correctly formed."
	ErrorReasonBadSignature              = "Bad Signature or signature info: the Interest carries an invalid signature."
	ErrorReasonInvalidParameters         = "Invalid parameters: the input from the requester is not expected."
	ErrorReasonNameNotAllowed            = "Name not allowed: the requested certificate name cannot be assigned to the requester."
	ErrorReasonBadValidityPeriod         = "Bad ValidityPeriod: requested certificate has an erroneous validity period, e.g., too long time."
	ErrorReasonRunOutOfTries             = "Run out of tries: the requester failed to complete the challenge within allowed number of attempts."
	ErrorReasonRunOutOfTime              = "Run out of time: the requester failed to complete the challenge within time limit."
	// NoAvailableNamesErr           = "No Available Names: the CA finds there is no namespaces available based on the PROBE parameters provided." // Currently unused (no support for PROBE)
)

var AvailableChallenges = []string{SelectedChallengeEmail}
var ErrorCodeMapping = map[ErrorCode]string{
	ErrorCodeBadInterestFormat: ErrorReasonBadInterestFormat,
	ErrorCodeBadParameter:      ErrorReasonBadParameterFormat,
	ErrorCodeBadSignature:      ErrorReasonBadSignature,
	ErrorCodeInvalidParameters: ErrorReasonInvalidParameters,
	ErrorCodeNameNotAllowed:    ErrorReasonNameNotAllowed,
	ErrorCodeBadValidityPeriod: ErrorReasonBadValidityPeriod,
	ErrorCodeRunOutOfTries:     ErrorReasonRunOutOfTries,
	ErrorCodeRunOutOfTime:      ErrorReasonRunOutOfTime,
}

type CaConfig struct {
	Ca struct {
		Name                         string `yaml:"name"`
		Info                         string `yaml:"name"`
		MaxCertificateValidityPeriod uint64 `yaml:"maxCertificateValidityPeriod"`
	}
}

type ChallengeRequestState struct {
	requestId           RequestId
	status              ChallengeStatus
	encryptionKey       [16]byte
	challengeType       ChallengeType
	emailChallengeState *EmailChallengeState
	challengeState      *ChallengeState
	clientPublicKey     []byte
}

type CaState struct {
	CaCert                enc.Wire
	CaInfo                string
	CaPrefix              string
	MaxCertValidityPeriod time.Duration
	SmtpModule            *email.SmtpModule

	ChallengeRequestStateMapping map[RequestId]*ChallengeRequestState
}

const negativeRequestIdOffset = -2

func NewCaState(caConfigFilePath string, smtpModule *email.SmtpModule) (*CaState, error) {
	caDetailsConfigFileBuffer, readFileError := os.ReadFile(caConfigFilePath)
	if readFileError != nil {
		return nil, readFileError
	}
	caDetails := &CaConfig{}
	caDetailsUnmarshalError := yaml.Unmarshal(caDetailsConfigFileBuffer, caDetails)
	if caDetailsUnmarshalError != nil {
		return nil, fmt.Errorf("in file %q: %w", caDetailsConfigFileBuffer, caDetailsUnmarshalError)
	}
	caState := &CaState{
		CaCert:                       nil,
		CaInfo:                       caDetails.Ca.Info,
		CaPrefix:                     caDetails.Ca.Name,
		MaxCertValidityPeriod:        time.Duration(caDetails.Ca.MaxCertificateValidityPeriod),
		SmtpModule:                   smtpModule,
		ChallengeRequestStateMapping: make(map[RequestId]*ChallengeRequestState),
	}
	return caState, nil
}

func (caState *CaState) Serve(ndnEngine ndn.Engine) error {
	// Set up INFO route
	caPrefixName, _ := enc.NameFromStr(caState.CaPrefix)
	caProfile := ndncert.CaProfile{
		CaPrefix:       caPrefixName,
		CaInfo:         caState.CaInfo,
		ParameterKey:   []string{},
		MaxValidPeriod: uint64(caState.MaxCertValidityPeriod.Seconds()),
		CaCertificate:  caState.CaCert,
	}

	infoPrefix, _ := enc.NameFromStr(caState.CaPrefix + "/" + PrefixInfo)
	ntSchema := schema.CreateFromJson(SchemaJson, map[string]any{})
	ntSchemaAttachError := ntSchema.Attach(infoPrefix, ndnEngine)
	if ntSchemaAttachError != nil {
		return ntSchemaAttachError
	}
	defer ntSchema.Detach()
	matchedNode := ntSchema.Root().Apply(enc.Matching{})
	version := matchedNode.Call("Provide", enc.Wire{caProfile.Encode().Join()})
	fmt.Printf("Generated CA Profile Packet with version= %d\n", version)

	// Set up NEW route
	newPrefix, _ := enc.NameFromStr(caState.CaPrefix + "/" + PrefixNew)
	ndnEngine.AttachHandler(newPrefix, func(interest ndn.Interest, rawInterest enc.Wire, sigCovered enc.Wire, reply ndn.ReplyFunc, deadline time.Time) {
		caState.OnNew(interest, rawInterest, sigCovered, reply, deadline)
	})

	// Set up CHALLENGE route
	challengePrefix, _ := enc.NameFromStr(caState.CaPrefix + "/" + PrefixChallenge)
	ndnEngine.AttachHandler(challengePrefix, func(interest ndn.Interest, rawInterest enc.Wire, sigCovered enc.Wire, reply ndn.ReplyFunc, deadline time.Time) {
		caState.OnChallenge(interest, rawInterest, sigCovered, reply, deadline)
	})

	return nil
}

func (caState *CaState) OnNew(interest ndn.Interest, rawInterest enc.Wire, sigCovered enc.Wire, reply ndn.ReplyFunc, deadline time.Time) {
	newInterest, _ := ndncert.ParseNewInterestAppParameters(enc.NewWireReader(interest.AppParam()), true)
	certRequestData, _, _ := spec_2022.Spec{}.ReadData(enc.NewBufferReader(newInterest.CertRequest))
	if *certRequestData.ContentType() != ndn.ContentTypeKey {
		replyWithError(ErrorCodeInvalidParameters, interest.Name(), reply)
		return
	}

	// TODO: add state for this - Specifically, the NotBefore field and NotAfter field in the certificate request should satisfy
	//request.NotBefore < request.NotAfter
	//request.NotBefore >= max(now - 120s, ca-certificate.NotBefore)
	//request.NotAfter <= min(now + max-validity-period, ca-certificate.NotAfter)

	ecdhState := getEcdhState(newInterest)
	salt := getSalt()
	requestId := getRequestId(caState)

	caState.ChallengeRequestStateMapping[requestId] = &ChallengeRequestState{
		requestId:           requestId,
		status:              ChallengeStatusNewInterestReceived,
		encryptionKey:       ([16]byte)(crypto.HKDF(ecdhState.GetSharedSecret(), salt)),
		challengeType:       TbdChallengeType,
		challengeState:      nil,
		emailChallengeState: nil,
		clientPublicKey:     certRequestData.Content().Join(),
	}

	newData := ndncert.NewData{
		EcdhPub:   ecdhState.PublicKey.Bytes(),
		Salt:      salt,
		RequestId: requestId[:],
		Challenge: AvailableChallenges,
	}

	newDataWire := newData.Encode()
	replyWithData(interest.Name(), newDataWire, reply)
}

func (caState *CaState) OnChallenge(interest ndn.Interest, rawInterest enc.Wire, sigCovered enc.Wire, reply ndn.ReplyFunc, deadline time.Time) {
	nameComponents := strings.Split(interest.Name().String(), "/")
	if len(nameComponents[len(nameComponents)+negativeRequestIdOffset]) != RequestIdLength {
		replyWithError(ErrorCodeBadInterestFormat, interest.Name(), reply)
		return
	}

	requestId := (RequestId)([]byte(nameComponents[len(nameComponents)+negativeRequestIdOffset]))
	encryptedMessageReader := enc.NewWireReader(interest.AppParam())
	encryptedMessage, _ := ndncert.ParseEncryptedMessage(encryptedMessageReader, true)
	initializationVector := ([crypto.NonceSizeBytes]byte)(encryptedMessage.InitializationVector)
	authenticationTag := ([crypto.TagSizeBytes]byte)(encryptedMessage.AuthenticationTag)
	encryptedMessageObject := crypto.EncryptedMessage{
		InitializationVector: initializationVector,
		AuthenticationTag:    authenticationTag,
		EncryptedPayload:     encryptedMessage.EncryptedPayload,
	}
	challengeRequestState, ok := caState.ChallengeRequestStateMapping[requestId]
	if !ok {
		replyWithError(ErrorCodeInvalidParameters, interest.Name(), reply)
		return
	}

	plaintext := crypto.DecryptPayload(challengeRequestState.encryptionKey, encryptedMessageObject, requestId)
	challengeInterestPlaintext, _ := ndncert.ParseChallengeInterestPlaintext(enc.NewBufferReader(plaintext), true)

	if !slices.Contains(AvailableChallenges, challengeInterestPlaintext.SelectedChallenge) {
		replyWithError(ErrorCodeInvalidParameters, interest.Name(), reply)
		return
	}

	switch {
	case challengeInterestPlaintext.SelectedChallenge == SelectedChallengeEmail:
		switch challengeRequestState.status {
		case ChallengeStatusNewInterestReceived:
			if len(challengeInterestPlaintext.Parameters) != 1 || challengeInterestPlaintext.Parameters[0].ParameterKey != ParameterKeyEmail {
				replyWithError(ErrorCodeInvalidParameters, interest.Name(), reply)
				return
			}
			if challengeRequestState.challengeState == nil {
				challengeRequestState.challengeState = NewChallengeState()
			}
			emailAddress := string(challengeInterestPlaintext.Parameters[0].ParameterValue)
			emailChallengeState, sendEmailStatus := NewEmailChallenge(caState.SmtpModule, emailAddress)
			remainingTimeUint64 := uint64(challengeRequestState.challengeState.Expiry.Second())
			if sendEmailStatus == email.StatusInvalidEmail {
				// TODO: Handle invalid email
				challengeRequestState.challengeState.RemainingAttempts -= 1
				if challengeRequestState.challengeState.RemainingAttempts == 0 {
					replyWithError(ErrorCodeRunOutOfTries, interest.Name(), reply)
					delete(caState.ChallengeRequestStateMapping, requestId)
					return
				}
				plaintextChallenge := ndncert.ChallengeDataPlaintext{
					Status:          ApplicationStatusCodeChallenge,
					ChallengeStatus: ChallengeStatusCodeInvalidEmail,
					RemainingTries:  &challengeRequestState.challengeState.RemainingAttempts,
					RemainingTime:   &remainingTimeUint64,
				}
				encryptedChallenge := crypto.EncryptPayload(challengeRequestState.encryptionKey, plaintextChallenge.Encode().Join(), requestId)
				challengeEncryptedMessage := ndncert.EncryptedMessage{
					InitializationVector: encryptedChallenge.InitializationVector[:],
					AuthenticationTag:    encryptedChallenge.AuthenticationTag[:],
					EncryptedPayload:     encryptedChallenge.EncryptedPayload,
				}
				replyWithData(interest.Name(), challengeEncryptedMessage.Encode(), reply)
				return
			}
			challengeRequestState.status = ChallengeStatusChallengeIssued
			plaintextChallenge := ndncert.ChallengeDataPlaintext{
				Status:          ApplicationStatusCodeChallenge,
				ChallengeStatus: ChallengeStatusCodeNeedCode,
				RemainingTries:  &challengeRequestState.challengeState.RemainingAttempts,
				RemainingTime:   &remainingTimeUint64,
			}
			encryptedChallenge := crypto.EncryptPayload(challengeRequestState.encryptionKey, plaintextChallenge.Encode().Join(), requestId)
			challengeEncryptedMessage := ndncert.EncryptedMessage{
				InitializationVector: encryptedChallenge.InitializationVector[:],
				AuthenticationTag:    encryptedChallenge.AuthenticationTag[:],
				EncryptedPayload:     encryptedChallenge.EncryptedPayload,
			}
			challengeRequestState.emailChallengeState = emailChallengeState
			replyWithData(interest.Name(), challengeEncryptedMessage.Encode(), reply)
		case ChallengeStatusChallengeIssued:
			if len(challengeInterestPlaintext.Parameters) != 1 || challengeInterestPlaintext.Parameters[0].ParameterKey != ParameterKeyCode {
				replyWithError(ErrorCodeInvalidParameters, interest.Name(), reply)
				return
			}
			if challengeRequestState.challengeState.Expiry.After(time.Now()) {
				replyWithError(ErrorCodeRunOutOfTime, interest.Name(), reply)
				delete(caState.ChallengeRequestStateMapping, requestId)
				return
			}
			secretCode := string(challengeInterestPlaintext.Parameters[0].ParameterValue)
			if secretCode != challengeRequestState.emailChallengeState.SecretCode {
				challengeRequestState.challengeState.RemainingAttempts -= 1
				remainingTimeUint64 := uint64(challengeRequestState.challengeState.Expiry.Second())
				if challengeRequestState.challengeState.RemainingAttempts == 0 {
					replyWithError(ErrorCodeRunOutOfTries, interest.Name(), reply)
					delete(caState.ChallengeRequestStateMapping, requestId)
					return
				}
				plaintextChallenge := ndncert.ChallengeDataPlaintext{
					Status:          ApplicationStatusCodeChallenge,
					ChallengeStatus: ChallengeStatusWrongCode,
					RemainingTries:  &challengeRequestState.challengeState.RemainingAttempts,
					RemainingTime:   &remainingTimeUint64,
				}
				encryptedChallenge := crypto.EncryptPayload(challengeRequestState.encryptionKey, plaintextChallenge.Encode().Join(), requestId)
				challengeEncryptedMessage := ndncert.EncryptedMessage{
					InitializationVector: encryptedChallenge.InitializationVector[:],
					AuthenticationTag:    encryptedChallenge.AuthenticationTag[:],
					EncryptedPayload:     encryptedChallenge.EncryptedPayload,
				}
				replyWithData(interest.Name(), challengeEncryptedMessage.Encode(), reply)
				return
			} else {
				plaintextSuccess := ndncert.ChallengeDataPlaintext{
					Status:                ApplicationStatusCodeSuccess,
					ChallengeStatus:       ChallengeStatusCodeSuccess,
					IssuedCertificateName: generateCertificateName(caState),
				}
				encryptedSuccess := crypto.EncryptPayload(challengeRequestState.encryptionKey, plaintextSuccess.Encode().Join(), requestId)
				successEncryptedMessage := ndncert.EncryptedMessage{
					InitializationVector: encryptedSuccess.InitializationVector[:],
					AuthenticationTag:    encryptedSuccess.AuthenticationTag[:],
					EncryptedPayload:     encryptedSuccess.EncryptedPayload,
				}
				replyWithData(interest.Name(), successEncryptedMessage.Encode(), reply)
				delete(caState.ChallengeRequestStateMapping, requestId)
			}
		}
	}
}

func getEcdhState(newInterestAppParameters *ndncert.NewInterestAppParameters) crypto.ECDHState {
	ecdhState := crypto.ECDHState{}
	ecdhState.GenerateKeyPair()
	ecdhState.SetRemotePublicKey(newInterestAppParameters.EcdhPub)
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

func replyWithError(errorCode ErrorCode, interestName enc.Name, reply ndn.ReplyFunc) {
	errorMessageContent := ndncert.ErrorMessage{
		ErrorCode: uint64(errorCode),
		ErrorInfo: ErrorCodeMapping[errorCode],
	}
	errorData, _, makeDataError := spec_2022.Spec{}.MakeData(
		interestName,
		&ndn.DataConfig{
			ContentType: utils.IdPtr(ndn.ContentTypeBlob),
		},
		errorMessageContent.Encode(),
		sec.NewSha256Signer())
	if makeDataError != nil {
		// TODO - handle error making error data packet.
		return
	}
	reply(errorData)
}

func replyWithData(interestName enc.Name, dataWire enc.Wire, reply ndn.ReplyFunc) {
	data, _, makeDataError := spec_2022.Spec{}.MakeData(
		interestName,
		&ndn.DataConfig{
			ContentType: utils.IdPtr(ndn.ContentTypeBlob),
			Freshness:   utils.IdPtr(4 * time.Second),
		},
		dataWire,
		sec.NewSha256Signer())
	if makeDataError != nil {
		// TODO - handle error making data packet
		return
	}
	reply(data)
}
