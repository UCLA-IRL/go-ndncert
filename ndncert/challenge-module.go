package ndncert

import (
	"go-ndncert/email"
	"math/rand"
	"time"
)

type SendEmailStatus uint64

const (
	SendEmailStatusOk SendEmailStatus = iota
	SendEmailStatusFailed
)

var maxAttempts uint64 = 3

const (
	secretLifetime int64 = 300 // in seconds
	secretLength   int   = 6
)

type ChallengeState struct {
	RemainingAttempts uint64
	Expiry            time.Time
}

type EmailChallengeState struct {
	Email          string
	SecretCode     string
	ChallengeState *ChallengeState
}

func NewEmailChallenge(emailAddress string) (*EmailChallengeState, SendEmailStatus) {
	var emailChallengeState = &EmailChallengeState{
		Email:          emailAddress,
		SecretCode:     generateSecretCode(),
		ChallengeState: newChallengeState(),
	}
	sendEmailStatus := emailChallengeState.sendEmail()
	if sendEmailStatus != SendEmailStatusOk {
		emailChallengeState = nil
	}
	return emailChallengeState, sendEmailStatus
}

func (e *EmailChallengeState) CheckCode(secret string) bool {
	return time.Now().Before(e.ChallengeState.Expiry) && secret == e.SecretCode
}

func generateSecretCode() string {
	var digits = []rune("0123456789")
	b := make([]rune, secretLength)
	for i := range b {
		b[i] = digits[rand.Intn(len(digits))]
	}
	return string(b)
}

func newChallengeState() *ChallengeState {
	return &ChallengeState{
		RemainingAttempts: maxAttempts,
		Expiry:            time.Now().Add(time.Second * time.Duration(secretLifetime)),
	}
}

func (e *EmailChallengeState) sendEmail() SendEmailStatus {
	secretEmail, status, _ := email.NewCodeEmail(e.Email, e.SecretCode)
	if status != email.Success {
		return SendEmailStatusFailed
	} else {
		sendStatus, _ := secretEmail.SendCodeEmail()
		if sendStatus != email.Success {
			return SendEmailStatusFailed
		}
	}
	return SendEmailStatusOk
}
