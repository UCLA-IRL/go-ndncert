//go:generate gondn_tlv_gen
package ndncert

import (
	enc "github.com/zjkmxy/go-ndn/pkg/encoding"
)

type CaProfile struct {
	//+field:name
	CaPrefix enc.Name `tlv:"0x81"`
	//+field:string
	CaInfo string `tlv:"0x83"`
	//+field:sequence:string:string
	ParameterKey []string `tlv:"0x85"`
	//+field:natural
	MaxValidPeriod uint64 `tlv:"0x8B"`
	//+field:wire
	CaCertificate enc.Wire `tlv:"0x89"`
}

type NewInterestAppParameters struct {
	//+field:binary
	EcdhPub []byte `tlv:"0x91"`
	//+field:binary
	CertRequest []byte `tlv:"0x93"`
}

type NewData struct {
	//+field:binary
	EcdhPub []byte `tlv:"0x91"`
	//+field:binary
	Salt []byte `tlv:"0x95"`
	//+field:binary
	RequestId []byte `tlv:"0x97"`
	//+field:sequence:string:string
	Challenge []string `tlv:"0x99"`
}

type EncryptedMessage struct {
	//+field:binary
	InitializationVector []byte `tlv:"0x9D"`
	//+field:binary
	AuthenticationTag []byte `tlv:"0xAF"`
	//+field:binary
	EncryptedPayload []byte `tlv:"0x9F"`
}

type ChallengeInterestPlaintext struct {
	//+field:string
	SelectedChallenge string `tlv:"0xA1"`
	//+field:map:string:string:0x87:[]byte:binary
	Parameters map[string][]byte `tlv:"0x85"`
}

type ChallengeDataPlaintext struct {
	//+field:natural
	Status uint64 `tlv:"0x9B"`
	//+field:string
	ChallengeStatus string `tlv:"0xA3"`
	//+field:name
	IssuedCertificateName enc.Name `tlv:"0xA9"`
	//+field:name
	ForwardingHint enc.Name `tlv:"0x1e"`
	//+field:natural:optional
	RemainingTries *uint64 `tlv:"0xA5"`
	//+field:natural:optional
	RemainingTime *uint64 `tlv:"0xA7"`
	//+field:map:string:string:0x87:[]byte:binary
	Parameters map[string][]byte `tlv:"0x85"`
}

type ErrorMessage struct {
	//+field:natural
	ErrorCode uint64 `tlv:"0xAB"`
	//+field:string
	ErrorInfo string `tlv:"0xAD"`
}
