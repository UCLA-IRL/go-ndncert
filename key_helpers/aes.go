package key_helpers

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"
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

func EncryptPayload(key [TagSizeBytes]byte, plaintext []byte, requestId [8]uint8) EncryptedMessage {
	block, cipherErr := aes.NewCipher(key[:])
	if cipherErr != nil {
		panic(cipherErr.Error())
	}

	nonce := make([]byte, NonceSizeBytes)
	if _, randReadErr := io.ReadFull(rand.Reader, nonce); randReadErr != nil {
		panic(randReadErr.Error())
	}

	aesgcm, encryptErr := cipher.NewGCM(block)
	if encryptErr != nil {
		panic(encryptErr.Error())
	}

	out := aesgcm.Seal(nil, nonce, plaintext, requestId[:])
	encryptedPayload := out[:len(plaintext)]
	authenticationTag := ([TagSizeBytes]byte)(out[len(plaintext):])
	initializationVector := ([NonceSizeBytes]byte)(nonce)

	return EncryptedMessage{
		initializationVector,
		authenticationTag,
		encryptedPayload,
	}
}

func DecryptPayload(key [16]byte, message EncryptedMessage, requestId [8]uint8) []byte {
	block, cipherErr := aes.NewCipher(key[:])
	if cipherErr != nil {
		panic(cipherErr.Error())
	}

	nonce := message.InitializationVector[:]

	aesgcm, encryptErr := cipher.NewGCM(block)
	if encryptErr != nil {
		panic(encryptErr.Error())
	}

	ciphertext := append(message.EncryptedPayload, message.AuthenticationTag[:]...)

	plaintext, err := aesgcm.Open(nil, nonce, ciphertext, requestId[:])
	if err != nil {
		panic(err.Error())
	}

	return plaintext
}
