package main

import (
	"fmt"
	"github.com/apex/log"
	enc "github.com/zjkmxy/go-ndn/pkg/encoding"
	basic_engine "github.com/zjkmxy/go-ndn/pkg/engine/basic"
	"github.com/zjkmxy/go-ndn/pkg/ndn"
	"github.com/zjkmxy/go-ndn/pkg/ndn/spec_2022"
	sec "github.com/zjkmxy/go-ndn/pkg/security"
	"go-ndncert/key_helpers"
	"go-ndncert/ndncert/client"
	"golang.org/x/term"
	"strings"
	"syscall"
)

func passAll(enc.Name, enc.Wire, ndn.Signature) bool {
	return true
}

// Specialized function to handle the specific certificate format of ndncert-cxx - cert name must follow
// the following convention - (Assuming email form username@domainname.extension) ca_prefix/extension/domain/username
func getCertNameFromEmailAddress(caPrefix string, emailAddress string) string {
	atSplit := strings.Split(emailAddress, "@")
	if len(atSplit) != 2 {
		return ""
	}
	dotSplit := strings.Split(atSplit[1], ".")
	var stringBuilder strings.Builder
	stringBuilder.WriteString(caPrefix)
	stringBuilder.WriteString("/" + atSplit[0])
	for i := len(dotSplit) - 1; i >= 0; i-- {
		stringBuilder.WriteString("/" + dotSplit[i])
	}
	return stringBuilder.String()
}

func main() {
	log.SetLevel(log.DebugLevel)
	logger := log.WithField("module", "main")

	caPrefix := "/ndn"

	// Start engine
	ndnTimer := basic_engine.NewTimer()
	ndnFace := basic_engine.NewStreamFace("unix", "/var/run/nfd.sock", true)
	ndnEngine := basic_engine.NewEngine(ndnFace, ndnTimer, sec.NewSha256IntSigner(ndnTimer), passAll)
	engineStartError := ndnEngine.Start()
	if engineStartError != nil {
		logger.Fatalf("Unable to start engine: %+v", engineStartError)
	}
	defer ndnEngine.Shutdown()

	// Get the CA's identity key from INFO request
	caInfoResult, infoInterestError := client.ExpressInfoInterest(ndnEngine, caPrefix)
	if infoInterestError != nil {
		logger.Fatalf("Encountered error fetching CA INFO: %+v", infoInterestError)
	}
	certKeyBits, _, certKeyBitsError := spec_2022.Spec{}.ReadData(enc.NewBufferReader(caInfoResult.CaCertificate))
	if certKeyBitsError != nil {
		logger.Fatal("Failed to parse certificate key bits data")
	}
	caPublicIdentityKey, parseCertificatePublicKeyError := key_helpers.ParsePublicKey(certKeyBits.Content().Join())
	if parseCertificatePublicKeyError != nil {
		logger.Fatalf("Failed to parse certificate public key from CA INFO: %+v", parseCertificatePublicKeyError)
	}

	// Here, we only allow the email to be done one time (else the program has to be re-run).
	// This is due to the fact that the cert-generated *should* be done when instantiating a new requester state
	// which subsequently requires a certificate following a specific format according to ndncert-cxx.
	var email string
	fmt.Print("Enter the email you wish to send the secret code to: ")
	fmt.Scanln(&email)
	requesterState, _ := client.NewRequesterState(caPrefix, getCertNameFromEmailAddress(caPrefix, email), caPublicIdentityKey, 3600, ndnEngine)
	newResult, newError := requesterState.ExpressNewInterest()
	if newError != nil {
		logger.Errorf("Encountered error in NEW: %+v", newError)
	}
	if newResult.ErrorMessage != nil {
		logger.Fatalf("Encountered error message in NEW: %+v", *newResult.ErrorMessage)
	}
	logger.Infof("NEW step succeeded with result %+v", newResult)
	emailChoiceChallengeResult, emailChoiceChallengeError := requesterState.ExpressEmailChoiceChallenge(email)
	if emailChoiceChallengeError != nil {
		logger.Fatalf("Encountered error email choice CHALLENGE step: %+v\n with error message: %+v", emailChoiceChallengeError, emailChoiceChallengeResult.ErrorMessage)
	}
	if emailChoiceChallengeResult.ErrorMessage != nil {
		logger.Fatalf("Encountered error message in NEW: %+v", *emailChoiceChallengeResult.ErrorMessage)
	}
	if *emailChoiceChallengeResult.ChallengeStatus == client.ChallengeStatusAfterSelectionChallengeData {
		logger.Infof("Email choice CHALLENGE step succeeded with result %+v", emailChoiceChallengeResult)
	}

	for {
		fmt.Print("Enter the secret code you received to your email: ")
		bytePassword, _ := term.ReadPassword(syscall.Stdin)
		emailCodeChallengeResult, emailCodeChallengeError := requesterState.ExpressEmailCodeChallenge(string(bytePassword))
		if emailCodeChallengeError != nil {
			logger.Fatalf("Encountered error email code CHALLENGE step: %+v\n with error message %+v", emailCodeChallengeError, *emailCodeChallengeResult.ErrorMessage)
		}
		if emailCodeChallengeResult.ErrorMessage != nil {
			logger.Fatalf("Encountered error message in NEW: %+v", *emailCodeChallengeResult.ErrorMessage)
		}
		if *emailCodeChallengeResult.ChallengeStatus == client.ChallengeStatusSuccess {
			logger.Infof("Email code CHALLENGE step succeeded with result %+v", emailCodeChallengeResult)
			break
		}
		logger.Infof("Email code CHALLENGE step failed with result %+v", emailCodeChallengeResult, emailCodeChallengeResult.ErrorMessage)
	}
}
