package server

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"github.com/apex/log"
	"github.com/dchest/uniuri"
	enc "github.com/zjkmxy/go-ndn/pkg/encoding"
	"github.com/zjkmxy/go-ndn/pkg/ndn"
	"github.com/zjkmxy/go-ndn/pkg/ndn/spec_2022"
	"github.com/zjkmxy/go-ndn/pkg/schema"
	_ "github.com/zjkmxy/go-ndn/pkg/schema/rdr"
	sec "github.com/zjkmxy/go-ndn/pkg/security"
	"github.com/zjkmxy/go-ndn/pkg/utils"
	"go-ndncert/email"
	"go-ndncert/key_helpers"
	"go-ndncert/ndncert"
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
		Info                         string `yaml:"info"`
		NotAfterNow                  uint64 `yaml:"notAfterNow"`
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
	clientPublicKey     *ecdsa.PublicKey
}

type CaState struct {
	//CaInfo                string
	//CaPrefix              string
	//IdentityKey           *ecdsa.PrivateKey
	//MaxCertValidityPeriod time.Duration
	//NotBefore             time.Time
	//NotAfter              time.Time
	CaPrefix       string
	CaInfo         string
	MaxValidPeriod time.Duration
	CaCert         *x509.Certificate
	CaCertBytes    []byte // In the case of a non-root CA, the signed certificate served must be passed in.
	IdentityKey    *ecdsa.PrivateKey
	SmtpModule     *email.SmtpModule
	Signer         ndn.Signer

	ChallengeRequestStateMapping map[RequestId]*ChallengeRequestState
}

const negativeRequestIdOffset = -2

func NewCaState(caPrefix string, caInfo string, maxValidPeriod uint64, caCert *x509.Certificate, caCertBytes []byte, identityKey *ecdsa.PrivateKey, smtpModule *email.SmtpModule) (*CaState, error) {
	// TODO: Figure out key locator name for CA's identity key
	keyLocatorName, _ := enc.NameFromStr("/ndn/edu/ucla/KEY")
	caState := &CaState{
		CaCert:                       caCert,
		CaCertBytes:                  caCertBytes,
		CaPrefix:                     caPrefix,
		CaInfo:                       caInfo,
		IdentityKey:                  identityKey,
		MaxValidPeriod:               time.Second * time.Duration(maxValidPeriod),
		SmtpModule:                   smtpModule,
		Signer:                       sec.NewEccSigner(false, false, time.Duration(0), identityKey, keyLocatorName),
		ChallengeRequestStateMapping: make(map[RequestId]*ChallengeRequestState),
	}
	return caState, nil
}

func (caState *CaState) Serve(ndnEngine ndn.Engine) error {
	logger := log.WithField("module", "ca")
	logger.Infof("Preparing to serve with CaState: %+v", caState)

	// Register the route
	caPrefixName, _ := enc.NameFromStr(caState.CaPrefix)
	logger.Infof("Setting up routing with ca prefix name: %s", caPrefixName)
	registerRouteError := ndnEngine.RegisterRoute(caPrefixName)
	if registerRouteError != nil {
		logger.Errorf("Failed to register route with ndn engine: %s", registerRouteError.Error())
		return registerRouteError
	}

	// Set up INFO route
	if caState.CaCertBytes == nil {
		// Create a self-signed certificate in the case we don't have a signed one (caCertBytes) passed in
		// We assume that this CA functions as a root CA
		certificateBytes, createCertificateError := x509.CreateCertificate(rand.Reader, caState.CaCert, caState.CaCert, &caState.IdentityKey.PublicKey, caState.IdentityKey)
		if createCertificateError != nil {
			logger.Errorf("Failed to generate certificate: %s", createCertificateError.Error())
			return createCertificateError
		}
		caState.CaCertBytes = certificateBytes
	}
	caProfile := ndncert.CaProfile{
		CaPrefix:       caPrefixName,
		CaInfo:         caState.CaInfo,
		ParameterKey:   []string{},
		MaxValidPeriod: uint64(caState.CaCert.NotAfter.Second()),
		CaCertificate:  enc.Wire{caState.CaCertBytes},
	}
	infoPrefix, _ := enc.NameFromStr(caState.CaPrefix + PrefixInfo)
	logger.Infof("Initializing INFO route on %s", infoPrefix.String())
	ntSchema := schema.CreateFromJson(SchemaJson, map[string]any{})
	ntSchemaAttachError := ntSchema.Attach(infoPrefix, ndnEngine)
	if ntSchemaAttachError != nil {
		logger.Errorf("Failed to initialize INFO route at nt schema attach: %s", ntSchemaAttachError.Error())
		return ntSchemaAttachError
	}

	matchedNode := ntSchema.Root().Apply(enc.Matching{})
	version := matchedNode.Call("Provide", caProfile.Encode())
	logger.Infof("Generated CA Profile Packet with version=%d", version)

	// Set up NEW route
	newPrefix, _ := enc.NameFromStr(caState.CaPrefix + PrefixNew)
	logger.Infof("Setting up NEW route on %s", newPrefix.String())
	attachNewPrefixHandlerError := ndnEngine.AttachHandler(newPrefix, func(interest ndn.Interest, rawInterest enc.Wire, sigCovered enc.Wire, reply ndn.ReplyFunc, deadline time.Time) {
		caState.OnNew(interest, rawInterest, sigCovered, reply, deadline)
	})
	if attachNewPrefixHandlerError != nil {
		logger.Errorf("Failed to attach NEW prefix handler: %s", attachNewPrefixHandlerError)
		return attachNewPrefixHandlerError
	}

	// Set up CHALLENGE route
	challengePrefix, _ := enc.NameFromStr(caState.CaPrefix + PrefixChallenge)
	logger.Infof("Setting up CHALLENGE route on %s", challengePrefix.String())
	attachChallengePrefixHandlerError := ndnEngine.AttachHandler(challengePrefix, func(interest ndn.Interest, rawInterest enc.Wire, sigCovered enc.Wire, reply ndn.ReplyFunc, deadline time.Time) {
		caState.OnChallenge(interest, rawInterest, sigCovered, reply, deadline)
	})
	if attachChallengePrefixHandlerError != nil {
		logger.Errorf("Failed to attach CHALLENGE prefix handler: %s", attachChallengePrefixHandlerError)
		return attachChallengePrefixHandlerError
	}

	return nil
}

func (caState *CaState) OnNew(interest ndn.Interest, rawInterest enc.Wire, sigCovered enc.Wire, reply ndn.ReplyFunc, deadline time.Time) {
	logger := log.WithField("module", "ca")
	logger.Infof("Handling incoming NEW Interest with name: %s", interest.Name().String())
	logger.Debugf("Raw interest app params: %s", interest.AppParam())
	newInterest, _ := ndncert.ParseNewInterestAppParameters(enc.NewWireReader(interest.AppParam()), true)
	logger.Debugf("succeeded parsing")
	certRequestData, certRequestSigCovered, readCertDataError := spec_2022.Spec{}.ReadData(enc.NewBufferReader(newInterest.CertRequest))
	if readCertDataError != nil {
		replyWithError(ErrorCodeInvalidParameters, interest.Name(), reply, caState.Signer)
		logger.Errorf("Bad NEW interest received with malformed data packet: %s", readCertDataError.Error())
		return
	}
	if *certRequestData.ContentType() != ndn.ContentTypeKey {
		replyWithError(ErrorCodeInvalidParameters, interest.Name(), reply, caState.Signer)
		logger.Error("Bad NEW interest received: content type is not KEY type")
		return
	}

	publicKey, publicKeyParsingError := key_helpers.ParsePublicKey(certRequestData.Content().Join())
	if publicKeyParsingError != nil {
		replyWithError(ErrorCodeBadInterestFormat, interest.Name(), reply, caState.Signer)
		logger.Error("Could not parse the public key from data payload")
		return
	}

	if !sec.EcdsaValidate(certRequestSigCovered, certRequestData.Signature(), publicKey) {
		logger.Error("Bad NEW interest received: bad certificate signature detected")
		replyWithError(ErrorCodeBadSignature, interest.Name(), reply, caState.Signer)
		return
	}
	logger.Infof("Validating with public key: %+v", publicKey)
	if !sec.EcdsaValidate(sigCovered, interest.Signature(), publicKey) {
		logger.Error("Bad CHALLENGE interest received: bad signature detected")
		replyWithError(ErrorCodeBadSignature, interest.Name(), reply, caState.Signer)
		return
	}

	notBefore, notAfter := certRequestData.Signature().Validity()
	if notBefore.After(*notAfter) {
		logger.Error("Bad NEW interest certificate received: notBefore comes after notAfter")
		replyWithError(ErrorCodeBadValidityPeriod, interest.Name(), reply, caState.Signer)
		return
	}
	if notBefore.Before(time.Now().Add(-120*time.Second)) || notBefore.Before(caState.CaCert.NotBefore) {
		logger.Error("Bad NEW interest certificate received: notBefore is greater than server limit")
		replyWithError(ErrorCodeBadValidityPeriod, interest.Name(), reply, caState.Signer)
		return
	}
	if notAfter.After(time.Now().Add(caState.MaxValidPeriod)) || notAfter.After(caState.CaCert.NotAfter) {
		logger.Errorf("notAfter: %+v, left: %+v, right %+v", notAfter, time.Now().Add(caState.MaxValidPeriod), caState.CaCert.NotAfter)
		logger.Error("Bad NEW interest certificate received: notAfter is lesser than server minimum")
		replyWithError(ErrorCodeBadValidityPeriod, interest.Name(), reply, caState.Signer)
		return
	}

	ecdhState := getEcdhState(newInterest)
	salt := getSalt()
	requestId := generateRequestId(caState)

	caState.ChallengeRequestStateMapping[requestId] = &ChallengeRequestState{
		requestId:           requestId,
		status:              ChallengeStatusNewInterestReceived,
		encryptionKey:       ([16]byte)(key_helpers.HKDF(ecdhState.GetSharedSecret(), salt)),
		challengeType:       TbdChallengeType,
		challengeState:      nil,
		emailChallengeState: nil,
		clientPublicKey:     publicKey,
	}

	newData := ndncert.NewData{
		EcdhPub:   ecdhState.PublicKey.Bytes(),
		Salt:      salt,
		RequestId: requestId[:],
		Challenge: AvailableChallenges,
	}

	newDataWire := newData.Encode()
	replyWithData(interest.Name(), newDataWire, reply, caState.Signer)
}

func (caState *CaState) OnChallenge(interest ndn.Interest, rawInterest enc.Wire, sigCovered enc.Wire, reply ndn.ReplyFunc, deadline time.Time) {
	logger := log.WithField("module", "ca")
	logger.Infof("interest name: %s", interest.Name().String())
	nameComponents := strings.Split(interest.Name().String(), "/")
	curRequestId := nameComponents[len(nameComponents)+negativeRequestIdOffset]
	curRequestIdLength := len(curRequestId)
	if curRequestIdLength != RequestIdLength {
		logger.Errorf(
			"Bad CHALLENGE interest received due request id of %s with length, should be %d but is %d",
			curRequestId, RequestIdLength, curRequestIdLength)
		replyWithError(ErrorCodeBadInterestFormat, interest.Name(), reply, caState.Signer)
		return
	}

	requestId := (RequestId)([]byte(nameComponents[len(nameComponents)+negativeRequestIdOffset]))
	challengeRequestState, ok := caState.ChallengeRequestStateMapping[requestId]
	if !ok {
		logger.Error("Bad CHALLENGE interest received: invalid request id detected")
		replyWithError(ErrorCodeInvalidParameters, interest.Name(), reply, caState.Signer)
		return
	}
	logger.Infof("Validating with public key: %+v", challengeRequestState.clientPublicKey)
	if !sec.EcdsaValidate(sigCovered, interest.Signature(), challengeRequestState.clientPublicKey) {
		logger.Error("Bad CHALLENGE interest received: bad signature detected")
		replyWithError(ErrorCodeBadSignature, interest.Name(), reply, caState.Signer)
		return
	}

	encryptedMessageReader := enc.NewWireReader(interest.AppParam())
	encryptedMessage, _ := ndncert.ParseEncryptedMessage(encryptedMessageReader, true)
	initializationVector := ([key_helpers.NonceSizeBytes]byte)(encryptedMessage.InitializationVector)
	authenticationTag := ([key_helpers.TagSizeBytes]byte)(encryptedMessage.AuthenticationTag)
	encryptedMessageObject := key_helpers.EncryptedMessage{
		InitializationVector: initializationVector,
		AuthenticationTag:    authenticationTag,
		EncryptedPayload:     encryptedMessage.EncryptedPayload,
	}

	plaintext := key_helpers.DecryptPayload(challengeRequestState.encryptionKey, encryptedMessageObject, requestId)
	challengeInterestPlaintext, _ := ndncert.ParseChallengeInterestPlaintext(enc.NewBufferReader(plaintext), true)

	if !slices.Contains(AvailableChallenges, challengeInterestPlaintext.SelectedChallenge) {
		logger.Error("Bad CHALLENGE interest received: invalid selected challenge detected")
		replyWithError(ErrorCodeInvalidParameters, interest.Name(), reply, caState.Signer)
		return
	}
	switch {
	case challengeInterestPlaintext.SelectedChallenge == SelectedChallengeEmail:
		switch challengeRequestState.status {
		case ChallengeStatusNewInterestReceived:
			if len(challengeInterestPlaintext.Parameters) != 1 {
				logger.Error("Bad CHALLENGE interest received: invalid email parameter detected")
				replyWithError(ErrorCodeInvalidParameters, interest.Name(), reply, caState.Signer)
				return
			}
			emailAddress, emailParameterPresent := challengeInterestPlaintext.Parameters[ParameterKeyEmail]
			if !emailParameterPresent {
				logger.Error("Bad CHALLENGE interest received: invalid email parameter detected")
				replyWithError(ErrorCodeInvalidParameters, interest.Name(), reply, caState.Signer)
				return
			}
			if challengeRequestState.challengeState == nil {
				challengeRequestState.challengeState = NewChallengeState()
			}
			emailChallengeState, sendEmailStatus := NewEmailChallenge(caState.SmtpModule, string(emailAddress))
			remainingTimeUint64 := uint64(challengeRequestState.challengeState.Expiry.Sub(time.Now()).Seconds())
			if sendEmailStatus == email.StatusInvalidEmail {
				logger.Error("Bad CHALLENGE interest received: invalid email parameter detected")
				challengeRequestState.challengeState.RemainingAttempts -= 1
				if challengeRequestState.challengeState.RemainingAttempts == 0 {
					replyWithError(ErrorCodeRunOutOfTries, interest.Name(), reply, caState.Signer)
					logger.Error("Due to bad email, the requester has run out of tries")
					delete(caState.ChallengeRequestStateMapping, requestId)
					return
				}
				plaintextChallenge := ndncert.ChallengeDataPlaintext{
					Status:          ApplicationStatusCodeChallenge,
					ChallengeStatus: ChallengeStatusCodeInvalidEmail,
					RemainingTries:  &challengeRequestState.challengeState.RemainingAttempts,
					RemainingTime:   &remainingTimeUint64,
				}
				encryptedChallenge := key_helpers.EncryptPayload(challengeRequestState.encryptionKey, plaintextChallenge.Encode().Join(), requestId)
				challengeEncryptedMessage := ndncert.EncryptedMessage{
					InitializationVector: encryptedChallenge.InitializationVector[:],
					AuthenticationTag:    encryptedChallenge.AuthenticationTag[:],
					EncryptedPayload:     encryptedChallenge.EncryptedPayload,
				}
				replyWithData(interest.Name(), challengeEncryptedMessage.Encode(), reply, caState.Signer)
				return
			}
			challengeRequestState.status = ChallengeStatusChallengeIssued
			plaintextChallenge := ndncert.ChallengeDataPlaintext{
				Status:          ApplicationStatusCodeChallenge,
				ChallengeStatus: ChallengeStatusCodeNeedCode,
				RemainingTries:  &challengeRequestState.challengeState.RemainingAttempts,
				RemainingTime:   &remainingTimeUint64,
			}
			encryptedChallenge := key_helpers.EncryptPayload(challengeRequestState.encryptionKey, plaintextChallenge.Encode().Join(), requestId)
			challengeEncryptedMessage := ndncert.EncryptedMessage{
				InitializationVector: encryptedChallenge.InitializationVector[:],
				AuthenticationTag:    encryptedChallenge.AuthenticationTag[:],
				EncryptedPayload:     encryptedChallenge.EncryptedPayload,
			}
			challengeRequestState.emailChallengeState = emailChallengeState
			replyWithData(interest.Name(), challengeEncryptedMessage.Encode(), reply, caState.Signer)
		case ChallengeStatusChallengeIssued:
			if len(challengeInterestPlaintext.Parameters) != 1 {
				logger.Error("Bad CHALLENGE interest received: invalid code parameter detected")
				replyWithError(ErrorCodeInvalidParameters, interest.Name(), reply, caState.Signer)
				return
			}
			secretCode, secretCodePresent := challengeInterestPlaintext.Parameters[ParameterKeyCode]
			if !secretCodePresent {
				logger.Error("Bad CHALLENGE interest received: invalid code parameter detected")
				replyWithError(ErrorCodeInvalidParameters, interest.Name(), reply, caState.Signer)
				return
			}
			if challengeRequestState.challengeState.Expiry.Before(time.Now()) {
				logger.Error("Requester has run out of time")
				replyWithError(ErrorCodeRunOutOfTime, interest.Name(), reply, caState.Signer)
				delete(caState.ChallengeRequestStateMapping, requestId)
				return
			}
			if string(secretCode) != challengeRequestState.emailChallengeState.SecretCode {
				logger.Error("Bad CHALLENGE interest received: secret code is incorrect")
				challengeRequestState.challengeState.RemainingAttempts -= 1
				remainingTimeUint64 := uint64(challengeRequestState.challengeState.Expiry.Second())
				if challengeRequestState.challengeState.RemainingAttempts == 0 {
					logger.Error("Due to bad code, the requester has run out of tries")
					replyWithError(ErrorCodeRunOutOfTries, interest.Name(), reply, caState.Signer)
					delete(caState.ChallengeRequestStateMapping, requestId)
					return
				}
				plaintextChallenge := ndncert.ChallengeDataPlaintext{
					Status:          ApplicationStatusCodeChallenge,
					ChallengeStatus: ChallengeStatusWrongCode,
					RemainingTries:  &challengeRequestState.challengeState.RemainingAttempts,
					RemainingTime:   &remainingTimeUint64,
				}
				encryptedChallenge := key_helpers.EncryptPayload(challengeRequestState.encryptionKey, plaintextChallenge.Encode().Join(), requestId)
				challengeEncryptedMessage := ndncert.EncryptedMessage{
					InitializationVector: encryptedChallenge.InitializationVector[:],
					AuthenticationTag:    encryptedChallenge.AuthenticationTag[:],
					EncryptedPayload:     encryptedChallenge.EncryptedPayload,
				}
				replyWithData(interest.Name(), challengeEncryptedMessage.Encode(), reply, caState.Signer)
				return
			} else {
				plaintextSuccess := ndncert.ChallengeDataPlaintext{
					Status:                ApplicationStatusCodeSuccess,
					ChallengeStatus:       ChallengeStatusCodeSuccess,
					IssuedCertificateName: generateCertificateName(caState),
				}
				encryptedSuccess := key_helpers.EncryptPayload(challengeRequestState.encryptionKey, plaintextSuccess.Encode().Join(), requestId)
				successEncryptedMessage := ndncert.EncryptedMessage{
					InitializationVector: encryptedSuccess.InitializationVector[:],
					AuthenticationTag:    encryptedSuccess.AuthenticationTag[:],
					EncryptedPayload:     encryptedSuccess.EncryptedPayload,
				}
				replyWithData(interest.Name(), successEncryptedMessage.Encode(), reply, caState.Signer)
				delete(caState.ChallengeRequestStateMapping, requestId)
			}
		}
	}
}

func getEcdhState(newInterestAppParameters *ndncert.NewInterestAppParameters) key_helpers.ECDHState {
	ecdhState := key_helpers.ECDHState{}
	ecdhState.GenerateKeyPair()
	ecdhState.SetRemotePublicKey(newInterestAppParameters.EcdhPub)
	return ecdhState
}

func getSalt() []byte {
	salt := make([]byte, sha256.New().Size())
	_, randReadError := rand.Read(salt)
	if randReadError != nil {
		panic(randReadError.Error())
	}
	return salt
}

func generateRequestId(caState *CaState) RequestId {
	randomRequestId, _ := randutil.Alphanumeric(RequestIdLength)
	requestId := (RequestId)([]byte(randomRequestId))
	if _, ok := caState.ChallengeRequestStateMapping[requestId]; ok {
		return generateRequestId(caState)
	}
	return requestId
}

func generateCertificateName(caState *CaState) enc.Name {
	// Generate random certificate name by taking ca prefix and appending a 16-long string
	certificateName, _ := enc.NameFromStr(caState.CaPrefix + "/" + uniuri.New())
	return certificateName
}

func replyWithError(errorCode ErrorCode, interestName enc.Name, reply ndn.ReplyFunc, ndnSigner ndn.Signer) {
	logger := log.WithField("module", "ca")
	logger.Infof("Replying with error")
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
		ndnSigner)
	if makeDataError != nil {
		logger.Fatalf("Failed to generate error data packet")
		return
	}
	errorDataReplyError := reply(errorData)
	if errorDataReplyError != nil {
		logger.Fatalf("Failed to reply with error")
		return
	}
}

func replyWithData(interestName enc.Name, dataWire enc.Wire, reply ndn.ReplyFunc, ndnSigner ndn.Signer) {
	logger := log.WithField("module", "ca")
	logger.Infof("Replying with data")
	data, _, makeDataError := spec_2022.Spec{}.MakeData(
		interestName,
		&ndn.DataConfig{
			ContentType: utils.IdPtr(ndn.ContentTypeBlob),
			Freshness:   utils.IdPtr(4 * time.Second),
		},
		dataWire,
		ndnSigner)
	if makeDataError != nil {
		logger.Fatalf("Failed to generate data packet")
		return
	}
	replyError := reply(data)
	if replyError != nil {
		logger.Fatalf("Failed to reply with data")
	}
}
