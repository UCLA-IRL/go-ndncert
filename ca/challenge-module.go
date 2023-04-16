package ca

import (
	"fmt"
	"math/rand"
	"ndn/ndncert/challenge/email"
	"time"
)

var maxAttempts uint = 3

const (
	secretLifetime int64 = 300 // in seconds
	secretLength   int   = 6
)

type ChallengeStatus int

const (
	ChallengeModuleBeforeEmail ChallengeStatus = iota
	ChallengeModuleNeedCode
	ChallengeModuleWrongCode
	ChallengeModuleFailure
	ChallengeModuleSuccess
)

type ChallengeState struct {
	RemainingAttempts uint
	Expiry            time.Time
	Status            ChallengeStatus
}

type EmailChallengeState struct {
	EmailChallenge
	ChallengeState
	Email      string
	SecretCode string
}

type EmailChallenge interface {
	generateSecretCode() string
	InitiateChallenge(email string) error
	CheckCode(secret uint) (bool, error)
	//HandleChallengeRequest() (string, )
	GetChallengeStatus() int
	sendEmail()
}

func (e *EmailChallengeState) InitiateChallenge() error {
	if e.Status != 0 {
		return fmt.Errorf("Challenge Already Initiated")
	}

	e.Status = ChallengeModuleNeedCode
	e.SecretCode = e.generateSecretCode()
	e.RemainingAttempts = maxAttempts
	e.Expiry = time.Now().Add(time.Second * time.Duration(secretLifetime))
	err := e.sendEmail()
	if err != nil {
		return err
	}
	return nil
}

func (e *EmailChallengeState) CheckCode(secret string) (ChallengeStatus, error) {
	if e.Status != ChallengeModuleNeedCode && e.Status != ChallengeModuleWrongCode {
		e.Status = ChallengeModuleFailure
		return e.Status, fmt.Errorf("Invalid state for challenge")
	} else if time.Now().After(e.Expiry) {
		e.Status = ChallengeModuleFailure
		return e.Status, fmt.Errorf("Challenge Expired")
	} else if secret != e.SecretCode {
		if e.RemainingAttempts > 1 {
			e.Status = ChallengeModuleWrongCode
			e.RemainingAttempts -= 1
			return e.Status, fmt.Errorf("Incorrect Secret Code")
		} else {
			e.RemainingAttempts -= 1
			return e.Status, fmt.Errorf("Incorrect Secret Code: No Tries Left")
		}
	} else {
		e.Status = ChallengeModuleSuccess
		return e.Status, nil
	}
}

func (e *EmailChallengeState) generateSecretCode() string {

	var digits = []rune("0123456789")
	b := make([]rune, secretLength)
	for i := range b {
		b[i] = digits[rand.Intn(len(digits))]
	}
	return string(b)
}

func (e *EmailChallengeState) sendEmail() error {
	secretEmail, status, err := email.NewCodeEmail(e.Email, e.SecretCode)
	if status != email.Success {
		return err
	} else {
		sendStatus, sendErr := secretEmail.SendCodeEmail()
		if sendStatus != email.Success {
			return sendErr
		}
	}
	return nil
}
