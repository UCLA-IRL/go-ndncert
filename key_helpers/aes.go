package key_helpers

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"io"
	"math"
)

const NonceSizeBytes = 12
const TagSizeBytes = 16

type EncryptedMessage struct {
	/**
	Initialization Vector (IV) 12 bytes in length consisting of
	64 bits randomly generated + 32 bits counter in big endian also known as nonce.
	*/
	InitializationVector [NonceSizeBytes]byte

	/**
	Authentication tag 16 bytes in length
	also known as a message authentication code (MAC).
	*/
	AuthenticationTag [TagSizeBytes]byte

	/**
	Encrypted payload
	*/
	EncryptedPayload []byte
}

const RandomSizeBytes = 8
const CounterSizeBytes = 4

type CryptoStatus uint64

const (
	CryptoStatusOk CryptoStatus = iota
	CryptoStatusError
	CryptoStatusInvalidCounter
)

type CounterInitializationVector struct {
	blockCounter uint32
	randomBytes  [RandomSizeBytes]byte
}

func GenerateCounterInitializationVector() *CounterInitializationVector {
	randomBytes := make([]byte, RandomSizeBytes)
	if _, randReadErr := io.ReadFull(rand.Reader, randomBytes); randReadErr != nil {
		panic(randReadErr.Error())
	}
	return &CounterInitializationVector{
		blockCounter: 0,
		randomBytes:  [RandomSizeBytes]byte(randomBytes),
	}
}

func EncryptPayload(key [TagSizeBytes]byte, plaintext []byte, requestId [8]uint8, counterInitializationVector *CounterInitializationVector) (*EncryptedMessage, CryptoStatus) {
	block, cipherErr := aes.NewCipher(key[:])
	if cipherErr != nil {
		return nil, CryptoStatusError
	}

	aesgcm, encryptErr := cipher.NewGCM(block)
	if encryptErr != nil {
		return nil, CryptoStatusError
	}

	counterInitializationVector.blockCounter += uint32(math.Ceil(float64(float32(len(plaintext)) / float32(TagSizeBytes))))
	counterBytes := make([]byte, CounterSizeBytes)
	binary.LittleEndian.PutUint32(counterBytes, counterInitializationVector.blockCounter)
	initializationVector := [12]byte(append(counterInitializationVector.randomBytes[:], counterBytes...))
	out := aesgcm.Seal(nil, initializationVector[:], plaintext, requestId[:])
	encryptedPayload := out[:len(plaintext)]
	authenticationTag := ([TagSizeBytes]byte)(out[len(plaintext):])

	return &EncryptedMessage{
		initializationVector,
		authenticationTag,
		encryptedPayload,
	}, CryptoStatusOk
}

func DecryptPayload(key [16]byte, message EncryptedMessage, requestId [8]uint8, previousBlockCounter *uint32) ([]byte, CryptoStatus) {
	block, cipherErr := aes.NewCipher(key[:])
	if cipherErr != nil {
		return nil, CryptoStatusError
	}

	nonce := message.InitializationVector[:]
	aesgcm, encryptErr := cipher.NewGCM(block)
	if encryptErr != nil {
		return nil, CryptoStatusError
	}

	ciphertext := append(message.EncryptedPayload, message.AuthenticationTag[:]...)
	plaintext, _ := aesgcm.Open(nil, nonce, ciphertext, requestId[:])
	//plaintextBlocks := uint32(math.Ceil(float64(float32(len(plaintext)) / float32(TagSizeBytes))))
	//if err != nil {
	//	return nil, CryptoStatusError
	//}
	//if *previousBlockCounter = *previousBlockCounter + plaintextBlocks; *previousBlockCounter != binary.BigEndian.Uint32(message.InitializationVector[RandomSizeBytes:]) {
	//	return nil, CryptoStatusInvalidCounter
	//}

	return plaintext, CryptoStatusOk
}
