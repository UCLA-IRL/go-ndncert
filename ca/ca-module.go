package ca

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	enc "github.com/zjkmxy/go-ndn/pkg/encoding"
	"github.com/zjkmxy/go-ndn/pkg/ndn"
	"github.com/zjkmxy/go-ndn/pkg/ndn/spec_2022"
	"github.com/zjkmxy/go-ndn/pkg/utils"
	"go-ndncert/crypto"
	"go-ndncert/schemaold"
	"go.step.sm/crypto/randutil"
	"strconv"
	"strings"
	"time"
)

type RequestType int64
type RequestStatus uint64
type ChallengeType int64

type RequestState struct {
	caPrefix enc.Name
	/**
	 * @brief The ID of the request.
	 */
	requestId [8]byte
	/**
	 * @brief The type of the request.
	 */
	requestType RequestType
	/**
	 * @brief The status of the request.
	 */
	status RequestStatus
	/**
	 * @brief The self-signed certificate in the request.
	 */
	cert ndn.Data
	/**
	 * @brief The encryption key for the client.
	 */
	encryptionKey [16]byte
	/**
	 * @brief The last Initialization Vector used by the AES encryption.
	 */
	encryptionIv []byte
	/**
	 * @brief The last Initialization Vector used by the other side's AES encryption.
	 */
	decryptionIv []byte
	/**
	 * @brief The challenge type.
	 */
	ChallengeType string

	ChallengeState *EmailChallengeState
}

const (
	CaModuleBeforeChallenge RequestStatus = iota
	CaModuleChallenge
	CaModulePending
	Success
	Failure
)

const (
	Probe RequestType = iota
	New
	Revoke
	Renew
)

const (
	Email ChallengeType = iota
)

const caName = "/ndn"
const minimumCertificateComponentSize = 4
const negativeKeyComponentOffset = -4
const keyString = "KEY"
const negativeRequestIdOffset = -2

var storage = make(map[[8]byte]*RequestState)
var availableChallenges = []string{"email"}

func validateName(certName string) {
	nameComponents := strings.Split(certName, "/")
	if len(nameComponents) < minimumCertificateComponentSize {
		// TODO: Add error handling for failure to meet number of certificate components
	}

	if nameComponents[len(nameComponents)+negativeKeyComponentOffset] != keyString {
		// TODO: Add error handling for failure to match keyString correctly
	}
}

func getEcdhState(newInt *schemaold.CmdNewInt) crypto.ECDHState {
	ecdhState := crypto.ECDHState{}
	ecdhState.GenerateKeyPair()
	ecdhState.SetRemotePublicKey(newInt.EcdhPub)

	return ecdhState
}

func getSalt() []byte {
	salt := make([]byte, sha256.New().Size())
	rand.Read(salt)

	return salt
}

func OnProfile() spec_2022.Data {
	// TODO: Respond with data info.
	return spec_2022.Data{}
}

func OnProbe(i ndn.Interest) spec_2022.Data {
	// TODO: Figure out how to respond?
	return spec_2022.Data{}
}

func OnNew(i ndn.Interest) spec_2022.Data {
	var requestState RequestState

	appParamReader := enc.NewWireReader(i.AppParam())
	newInt, err := schemaold.ParseCmdNewInt(appParamReader, true)
	if err != nil {
		// TODO: Handle error if parser fails to handle "NEW" interest packet.
	}

	certReqReader := enc.NewBufferReader(newInt.CertReq)
	certReqData, _, err := spec_2022.Spec{}.ReadData(certReqReader)
	if err != nil {
		// TODO: Handle error if certificate request reading fails.
	}

	caPrefixName, err := enc.NameFromStr(caName)
	if !caPrefixName.IsPrefix(certReqData.Name()) {
		// TODO: Handle error if the cA name is not a prefix of the request data name.
	}

	validateName(certReqData.Name().String())

	ecdhState := getEcdhState(newInt)
	salt := getSalt()
	symmetricKey := ([16]byte)(crypto.HKDF(ecdhState.GetSharedSecret(), salt))

	requestState.requestType = New
	requestState.caPrefix = caPrefixName

	_requestId, _ := randutil.Alphanumeric(8)
	requestId := ([8]byte)([]byte(_requestId))

	contentType := ndn.ContentTypeBlob
	fourSeconds := 4 * time.Second

	cmdNewData := schemaold.CmdNewData{
		EcdhPub: ecdhState.PublicKey.Bytes(),
		Salt:    salt, ReqId: requestId[:],
		Challenge: availableChallenges,
	}

	cmdNewDataWire := cmdNewData.Encode()

	storage[requestId] = &RequestState{
		caPrefix:      caPrefixName,
		requestId:     requestId,
		requestType:   New,
		status:        CaModuleBeforeChallenge,
		cert:          certReqData,
		encryptionKey: symmetricKey,
	}

	return spec_2022.Data{
		NameV: i.Name(),
		MetaInfo: &spec_2022.MetaInfo{
			ContentType:     utils.ConvIntPtr[ndn.ContentType, uint64](&contentType),
			FreshnessPeriod: &fourSeconds,
			FinalBlockID:    nil,
		},
		ContentV:       cmdNewDataWire,
		SignatureInfo:  nil,
		SignatureValue: nil,
	}
}

func OnChallenge(i ndn.Interest) spec_2022.Data {
	nameComponents := strings.Split(i.Name().String(), "/")
	requestId := ([8]byte)([]byte(nameComponents[len(nameComponents)+negativeRequestIdOffset]))

	cipherMsgReader := enc.NewWireReader(i.AppParam())
	cipherMsg, err := schemaold.ParseCipherMsg(cipherMsgReader, true)
	if err != nil {
		panic(err.Error())
	}

	initializationVector := ([crypto.NonceSizeBytes]byte)(cipherMsg.InitVec)
	authenticationTag := ([crypto.TagSizeBytes]byte)(cipherMsg.AuthNTag)

	encryptedMsg := crypto.EncryptedMessage{
		InitializationVector: initializationVector,
		AuthenticationTag:    authenticationTag,
		EncryptedPayload:     cipherMsg.Payload,
	}

	fmt.Printf("requestId: %s\n", requestId)
	requestState := storage[requestId]

	plaintext := crypto.DecryptPayload(requestState.encryptionKey, encryptedMsg, requestId)
	plaintextReader := enc.NewBufferReader(plaintext)
	challengeIntPlaintext, err := schemaold.ParseChallengeIntPlain(plaintextReader, true)
	if err != nil {
		println(challengeIntPlaintext)
		panic(err.Error())
	}

	if challengeIntPlaintext.SelectedChal != "email" {
		panic(fmt.Errorf("Only Supports Email Challenge!"))
	}

	var chalData schemaold.ChallengeDataPlain

	if requestState.status == CaModuleBeforeChallenge {
		emailAddress := string(challengeIntPlaintext.Params[0].ParamValue)
		requestState.ChallengeType = challengeIntPlaintext.SelectedChal
		requestState.ChallengeState = &EmailChallengeState{Email: emailAddress}
		err := requestState.ChallengeState.InitiateChallenge()
		if err != nil {
			//TODO: Prepare Error Data Packet
		}
		requestState.status = CaModuleChallenge
		challengeStatus := uint64(requestState.ChallengeState.Status)
		remainTries := uint64(requestState.ChallengeState.RemainingAttempts)
		expiry := requestState.ChallengeState.Expiry
		diff := uint64(expiry.Sub(time.Now()).Seconds())
		chalData = schemaold.ChallengeDataPlain{
			Status:      uint64(requestState.status),
			ChalStatus:  &challengeStatus,
			RemainTries: &remainTries,
			RemainTime:  &diff,
		}
	} else if requestState.status == CaModuleChallenge {
		if challengeIntPlaintext.Params[0].ParamKey != "code" {
			//TODO: Prepare Error Packet
		}
		code := string(challengeIntPlaintext.Params[0].ParamValue)
		status, _ := requestState.ChallengeState.CheckCode(code)
		if status == ChallengeModuleFailure {
			delete(storage, requestId)
			// TODO: Prepare Error Data Packet

		} else if status == ChallengeModuleWrongCode {
			challengeStatus := uint64(requestState.ChallengeState.Status)
			remainTries := uint64(requestState.ChallengeState.RemainingAttempts)
			expiry := requestState.ChallengeState.Expiry
			diff := uint64(expiry.Sub(time.Now()).Seconds())
			chalData = schemaold.ChallengeDataPlain{
				Status:      uint64(requestState.status),
				ChalStatus:  &challengeStatus,
				RemainTries: &remainTries,
				RemainTime:  &diff,
			}
		} else {
			requestState.status = CaModulePending
			//TODO: Issue Certificate
			delete(storage, requestId)
			requestState.status = Success
			challengeStatus := uint64(requestState.ChallengeState.Status)
			millisecondTS := strconv.FormatInt(time.Now().UnixMilli(), 10)
			certName := requestState.cert.Name()
			certNamePrefix := requestState.cert.Name()[:len(certName)+negativeKeyComponentOffset+2].String()

			newCertName, _ := enc.NameFromStr(certNamePrefix + "/NDNCERT/" + millisecondTS)

			chalData = schemaold.ChallengeDataPlain{
				Status:     uint64(requestState.status),
				ChalStatus: &challengeStatus,
				CertName:   newCertName,
			}
		}
	}

	chalDataBuf := chalData.Encode().Join()
	chalDataEncryptedMessage := crypto.EncryptPayload(requestState.encryptionKey, chalDataBuf, requestId)
	chalDataCiphertext := schemaold.CipherMsg{
		InitVec:  chalDataEncryptedMessage.InitializationVector[:],
		AuthNTag: chalDataEncryptedMessage.AuthenticationTag[:],
		Payload:  chalDataEncryptedMessage.EncryptedPayload,
	}
	chalDataCiphertextBuf := chalDataCiphertext.Encode()
	contentType := ndn.ContentTypeBlob
	fourSeconds := 4 * time.Second
	return spec_2022.Data{
		NameV: i.Name(),
		MetaInfo: &spec_2022.MetaInfo{
			ContentType:     utils.ConvIntPtr[ndn.ContentType, uint64](&contentType),
			FreshnessPeriod: &fourSeconds,
			FinalBlockID:    nil,
		},
		ContentV:       chalDataCiphertextBuf,
		SignatureInfo:  nil,
		SignatureValue: nil,
	}
}
