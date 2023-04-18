package ca

import (
	"crypto/sha256"
	"fmt"
	enc "github.com/zjkmxy/go-ndn/pkg/encoding"
	"github.com/zjkmxy/go-ndn/pkg/ndn"
	"github.com/zjkmxy/go-ndn/pkg/ndn/spec_2022"
	"github.com/zjkmxy/go-ndn/pkg/security"
	"github.com/zjkmxy/go-ndn/pkg/utils"
	"go-ndncert/crypto"
	"go-ndncert/schemaold"
	"testing"
)

func TestOnNew(t *testing.T) {

	ecdhState := crypto.ECDHState{}
	ecdhState.GenerateKeyPair()

	name, err := enc.NameFromStr("/ndn/user/name/KEY/1/version/4")
	if err != nil {
		print(err.Error())
	}
	wire, _, _ := spec_2022.Spec{}.MakeData(
		name,
		&ndn.DataConfig{
			ContentType: utils.IdPtr(ndn.ContentTypeBlob),
		},
		nil,
		security.NewSha256Signer(),
	)

	appParams := schemaold.CmdNewInt{
		EcdhPub: ecdhState.PublicKey.Bytes(),
		CertReq: wire.Join(),
	}

	appParamsWire := appParams.Encode()
	h := sha256.New()
	h.Write(appParamsWire.Join())

	digest := h.Sum(nil)
	name1, _ := enc.NameFromStr(fmt.Sprintf("/ndn/CA/NEW/params-sha256=%x", digest))
	println(name1.String())

	i := &spec_2022.Interest{
		NameV:                 name1,
		CanBePrefixV:          false,
		MustBeFreshV:          true,
		SignatureInfo:         nil,
		SignatureValue:        nil,
		ApplicationParameters: appParamsWire,
	}

	dp := OnNew(i)

	dataBuff := dp.Content().Join()
	dataBuffWireReader := enc.NewBufferReader(dataBuff)
	cmdNewData, err := schemaold.ParseCmdNewData(dataBuffWireReader, true)

	ecdhState.SetRemotePublicKey(cmdNewData.EcdhPub)
	sharedSecret := ecdhState.GetSharedSecret()

	symmetricKey := crypto.HKDF(sharedSecret, cmdNewData.Salt)

	challengeParams := []*schemaold.Param{{
		ParamKey:   "email",
		ParamValue: []byte("tanmaya2000@hotmail.com"),
	}}

	challengeIntPlaintext := schemaold.ChallengeIntPlain{
		SelectedChal: "email",
		Params:       challengeParams,
	}

	var symmetricKeyFixed [16]byte
	var requestIdFixed [8]byte

	copy(symmetricKeyFixed[:], symmetricKey)
	copy(requestIdFixed[:], cmdNewData.ReqId)

	challengeIntPlaintextBytes := challengeIntPlaintext.Encode().Join()

	challengeIntEncryptedMessage := crypto.EncryptPayload(symmetricKeyFixed, challengeIntPlaintextBytes, requestIdFixed)
	cipherMsgInt := schemaold.CipherMsg{
		InitVec:  challengeIntEncryptedMessage.InitializationVector[:],
		AuthNTag: challengeIntEncryptedMessage.AuthenticationTag[:],
		Payload:  challengeIntEncryptedMessage.EncryptedPayload,
	}

	cipherMsgWire := cipherMsgInt.Encode()
	h = sha256.New()
	h.Write(cipherMsgWire.Join())

	cipherDig := h.Sum(nil)

	name2, _ := enc.NameFromStr(fmt.Sprintf("/ndn/CA/CHALLENGE/%s/params-sha256=%x", cmdNewData.ReqId, cipherDig))
	println(name2.String())
	ichal := &spec_2022.Interest{
		NameV:                 name2,
		CanBePrefixV:          false,
		MustBeFreshV:          true,
		SignatureInfo:         nil,
		SignatureValue:        nil,
		ApplicationParameters: cipherMsgInt.Encode(),
	}

	dpchal := OnChallenge(ichal)
	dataBuff = dpchal.Content().Join()
	dataBuffWireReader = enc.NewBufferReader(dataBuff)

	cipherMsg, _ := schemaold.ParseCipherMsg(dataBuffWireReader, true)
	var cipherMsgInitVecFixed [crypto.NonceSizeBytes]byte
	var cipherMsgAuthNTagFixed [crypto.TagSizeBytes]byte

	copy(cipherMsgInitVecFixed[:], cipherMsg.InitVec)
	copy(cipherMsgAuthNTagFixed[:], cipherMsg.AuthNTag)

	plainText := crypto.DecryptPayload(symmetricKeyFixed, crypto.EncryptedMessage{
		InitializationVector: cipherMsgInitVecFixed,
		AuthenticationTag:    cipherMsgAuthNTagFixed,
		EncryptedPayload:     cipherMsg.Payload,
	}, requestIdFixed)

	cmdChalPlainReader := enc.NewBufferReader(plainText)
	cmdChalPlain, _ := schemaold.ParseChallengeDataPlain(cmdChalPlainReader, true)

	t.Logf("Request Status: %d", cmdChalPlain.Status)
	t.Logf("Challenge Status: %d", *cmdChalPlain.ChalStatus)
	t.Logf("Remaining Time: %d", *cmdChalPlain.RemainTime)
	t.Logf("Remaining Tries: %d", *cmdChalPlain.RemainTries)

	//fmt.Println("Please enter the secret code sent to your email: ")
	//var userCode string
	//fmt.Scanln(&userCode)

	codeParams := []*schemaold.Param{{
		ParamKey:   "code",
		ParamValue: []byte("123456"),
	}}

	codeIntPlaintext := schemaold.ChallengeIntPlain{
		SelectedChal: "email",
		Params:       codeParams,
	}

	codeIntPlaintextBytes := codeIntPlaintext.Encode().Join()

	codeIntEncryptedMessage := crypto.EncryptPayload(symmetricKeyFixed, codeIntPlaintextBytes, requestIdFixed)
	codeMsgInt := schemaold.CipherMsg{
		InitVec:  codeIntEncryptedMessage.InitializationVector[:],
		AuthNTag: codeIntEncryptedMessage.AuthenticationTag[:],
		Payload:  codeIntEncryptedMessage.EncryptedPayload,
	}

	codeMsgIntWire := codeMsgInt.Encode()
	h = sha256.New()
	h.Write(codeMsgIntWire.Join())

	codeMsgDig := h.Sum(nil)

	name3, _ := enc.NameFromStr(fmt.Sprintf("/ndn/CA/CHALLENGE/%s/params-sha256=%x", cmdNewData.ReqId, codeMsgDig))
	println(name3.String())

	icode := &spec_2022.Interest{
		NameV:                 name3,
		CanBePrefixV:          false,
		MustBeFreshV:          true,
		SignatureInfo:         nil,
		SignatureValue:        nil,
		ApplicationParameters: codeMsgInt.Encode(),
	}

	dpcode := OnChallenge(icode)

	dataBuff = dpcode.Content().Join()
	dataBuffWireReader = enc.NewBufferReader(dataBuff)

	cipherMsg, _ = schemaold.ParseCipherMsg(dataBuffWireReader, true)

	copy(cipherMsgInitVecFixed[:], cipherMsg.InitVec)
	copy(cipherMsgAuthNTagFixed[:], cipherMsg.AuthNTag)

	plainText = crypto.DecryptPayload(symmetricKeyFixed, crypto.EncryptedMessage{
		InitializationVector: cipherMsgInitVecFixed,
		AuthenticationTag:    cipherMsgAuthNTagFixed,
		EncryptedPayload:     cipherMsg.Payload,
	}, requestIdFixed)

	cmdCodePlainReader := enc.NewBufferReader(plainText)
	cmdCodePlain, _ := schemaold.ParseChallengeDataPlain(cmdCodePlainReader, true)

	t.Logf("Request Status: %d", cmdCodePlain.Status)
	t.Logf("Challenge Status: %d", *cmdCodePlain.ChalStatus)
	if uint64(Success) == cmdCodePlain.Status {
		t.Logf("Issued CertName: %s", cmdCodePlain.CertName.String())
	} else {
		t.Logf("Remaining Time: %d", *cmdCodePlain.RemainTime)
		t.Logf("Remaining Tries: %d", *cmdCodePlain.RemainTries)
	}
}
