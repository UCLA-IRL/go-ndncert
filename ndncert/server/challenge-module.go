package server

import (
	"math/rand"
	"net/mail"
	"time"

	"github.com/UCLA-IRL/go-ndncert/email"
)

var maxAttempts uint64 = 3

const (
	secretLifetime   uint64 = 300 // in seconds
	SecretCodeLength int    = 6
)

type ChallengeState struct {
	RemainingAttempts uint64
	Expiry            time.Time
}

type EmailChallengeState struct {
	Email      string
	SecretCode string
}

func NewEmailChallenge(smtpModule *email.SmtpModule, emailAddress string) (*EmailChallengeState, email.Status) {
	_, emailErr := mail.ParseAddress(emailAddress)
	if emailErr != nil {
		return nil, email.StatusInvalidEmail
	}
	emailChallengeState := &EmailChallengeState{
		Email:      emailAddress,
		SecretCode: generateSecretCode(),
	}
	sendEmailStatus, _ := smtpModule.SendCodeEmail(emailChallengeState.Email, emailChallengeState.SecretCode)
	return emailChallengeState, sendEmailStatus
}

func NewChallengeState() *ChallengeState {
	return &ChallengeState{
		RemainingAttempts: maxAttempts,
		Expiry:            time.Now().Add(time.Second * time.Duration(secretLifetime)),
	}
}

func generateSecretCode() string {
	var digits = []rune("0123456789")
	b := make([]rune, SecretCodeLength)
	for i := range b {
		b[i] = digits[rand.Intn(len(digits))]
	}
	return string(b)
}
