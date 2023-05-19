package email

import (
	"fmt"
	"gopkg.in/yaml.v3"
	"net/mail"
	"net/smtp"
	"os"
	"regexp"
)

const smtpConfigFilePath = "../config/smtp.yml"
const codeEmailSubjectLine = "Subject: Your NDN Email Challenge Secret Pin"

type Status int

type SMTPAuth struct {
	Smtp struct {
		Identity string `yaml:"identity"`
		Username string `yaml:"username"`
		Password string `yaml:"password"`
		Host     string `yaml:"host"`
		Port     int64  `yaml:"port"`
	}
}

type CodeEmail struct {
	ChallengeEmail string
	ChallengeCode  string
}

const (
	StatusSuccess Status = iota
	StatusInvalidEmail
	StatusError
)

func readSmtpConfig() (*SMTPAuth, error) {
	buf, err := os.ReadFile(smtpConfigFilePath)
	if err != nil {
		return nil, err
	}

	c := &SMTPAuth{}
	err = yaml.Unmarshal(buf, c)
	if err != nil {
		return nil, fmt.Errorf("in file %q: %w", smtpConfigFilePath, err)
	}

	return c, err
}

func NewCodeEmail(e string, c string) (CodeEmail, Status, error) {
	_, emailErr := mail.ParseAddress(e)
	if emailErr != nil {
		return CodeEmail{}, StatusInvalidEmail, fmt.Errorf("invalid email address %s: failed to match regex", e)
	}

	codeMatcher := regexp.MustCompile("^\\d{6}$")
	isMatch := codeMatcher.Match([]byte(c))
	if !isMatch {
		return CodeEmail{}, StatusInvalidEmail, fmt.Errorf("invalid code %s: failed to match regex", c)
	}

	return CodeEmail{e, c}, StatusSuccess, nil
}

func (c CodeEmail) SendCodeEmail() (Status, error) {
	conf, readSmtpConfigErr := readSmtpConfig()
	if readSmtpConfigErr != nil {
		return StatusError, fmt.Errorf("failed to read config file from path: %s", smtpConfigFilePath)
	}

	address := fmt.Sprintf("%s:%d", conf.Smtp.Host, conf.Smtp.Port)
	auth := smtp.PlainAuth(conf.Smtp.Identity, conf.Smtp.Username, conf.Smtp.Password, conf.Smtp.Host)
	from := conf.Smtp.Identity
	to := []string{c.ChallengeEmail}
	subject := fmt.Sprintf("From: <%s>\r\nTo: <%s>\r\n%s\r\n\r\n",
		from,
		to,
		codeEmailSubjectLine)
	body := fmt.Sprintf("Secret  PIN: %s\r\n", c.ChallengeCode)
	message := []byte(subject + body)

	sendMailErr := smtp.SendMail(address, auth, from, to, message)

	if sendMailErr != nil {
		return StatusError, fmt.Errorf("failed to send code challenge email to %s", c.ChallengeEmail)
	}

	return StatusSuccess, nil
}
