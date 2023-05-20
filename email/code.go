package email

import (
	"fmt"
	"gopkg.in/yaml.v3"
	"net/smtp"
	"os"
)

//const codeEmailSubjectLine = "Subject: Your NDN Email Challenge Secret Pin"

type Status int

type SMTPConfig struct {
	Smtp struct {
		Identity string `yaml:"identity"`
		Username string `yaml:"username"`
		Password string `yaml:"password"`
		Host     string `yaml:"host"`
		Port     int64  `yaml:"port"`
	}
	Email struct {
		CodeEmailBody        string `yaml:"codeEmailSubjectLine"`
		CodeEmailSubjectLine string `yaml:"codeEmailSubjectLine"`
	}
}

type SmtpModule struct {
	Address              string
	Auth                 smtp.Auth
	CodeEmailBody        string
	CodeEmailSubjectLine string
	OriginEmail          string
}

const (
	StatusSuccess Status = iota
	StatusInvalidEmail
	StatusError
)

func NewSmtpModule(smtpConfigFilePath string) (*SmtpModule, error) {
	smtpConfigFileBuffer, readFileError := os.ReadFile(smtpConfigFilePath)
	if readFileError != nil {
		return nil, readFileError
	}
	smtpConfig := &SMTPConfig{}
	smtpConfigUnmarshalError := yaml.Unmarshal(smtpConfigFileBuffer, smtpConfig)
	if smtpConfigUnmarshalError != nil {
		return nil, fmt.Errorf("in file %q: %w", smtpConfigFilePath, smtpConfigUnmarshalError)
	}
	smtpModule := &SmtpModule{
		Address:              fmt.Sprintf("%s:%d", smtpConfig.Smtp.Host, smtpConfig.Smtp.Port),
		Auth:                 smtp.PlainAuth(smtpConfig.Smtp.Identity, smtpConfig.Smtp.Username, smtpConfig.Smtp.Password, smtpConfig.Smtp.Host),
		CodeEmailBody:        smtpConfig.Email.CodeEmailBody,
		CodeEmailSubjectLine: smtpConfig.Email.CodeEmailSubjectLine,
		OriginEmail:          smtpConfig.Smtp.Identity,
	}
	return smtpModule, nil
}

func (smtpModule *SmtpModule) SendCodeEmail(challengeEmail string, challengeCode string) (Status, error) {
	subject := fmt.Sprintf("From: <%s>\r\nTo: <%s>\r\n%s\r\n\r\n",
		smtpModule.OriginEmail,
		[]string{challengeEmail},
		smtpModule.CodeEmailSubjectLine)
	body := fmt.Sprintf("%s %s\r\n", smtpModule.CodeEmailBody, challengeCode)
	message := []byte(subject + body)
	sendMailErr := smtp.SendMail(smtpModule.Address, smtpModule.Auth, smtpModule.OriginEmail, []string{challengeEmail}, message)

	if sendMailErr != nil {
		return StatusError, fmt.Errorf("failed to send code challenge email to %s", challengeEmail)
	}

	return StatusSuccess, nil
}
