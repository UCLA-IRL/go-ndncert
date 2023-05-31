package main

import (
	"fmt"
	"github.com/apex/log"
	enc "github.com/zjkmxy/go-ndn/pkg/encoding"
	basic_engine "github.com/zjkmxy/go-ndn/pkg/engine/basic"
	"github.com/zjkmxy/go-ndn/pkg/ndn"
	sec "github.com/zjkmxy/go-ndn/pkg/security"
	"go-ndncert/key_helpers"
	"go-ndncert/ndncert/client"
	"golang.org/x/term"
	"syscall"
)

func passAll(enc.Name, enc.Wire, ndn.Signature) bool {
	return true
}

func main() {
	log.SetLevel(log.DebugLevel)
	logger := log.WithField("module", "main")

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
	caInfoResult, infoInterestError := client.ExpressInfoInterest(ndnEngine, "/ndn/edu/ucla")
	if infoInterestError != nil {
		logger.Fatalf("Encountered error fetching CA INFO: %+v", infoInterestError)
	}
	caPublicIdentityKey, parseCertificatePublicKeyError := key_helpers.ParseCertificatePublicKey(caInfoResult.CaCertificate)
	if parseCertificatePublicKeyError != nil {
		logger.Fatalf("Failed to parse certificate public key from CA INFO: %+v", parseCertificatePublicKeyError)
	}

	requesterState, _ := client.NewRequesterState("client", "/ndn/edu/ucla", caPublicIdentityKey, 86300, ndnEngine)
	newResult, newError := requesterState.ExpressNewInterest()
	if newError != nil {
		logger.Fatalf("Encountered error in NEW: %+v", newError)
	}
	logger.Infof("NEW step succeeded with result %+v", newResult)
	for {
		var email string
		fmt.Print("Enter the email you wish to send the secret code to: ")
		fmt.Scanln(&email)
		challengeResult, challengeError := requesterState.ExpressEmailChoiceChallenge(email)
		if challengeError != nil {
			logger.Fatalf("Encountered error email choice CHALLENGE step: %+v", challengeError)
		}
		if challengeResult.ChallengeStatus == client.ChallengeStatusAfterSelectionChallengeData {
			logger.Infof("Email choice CHALLENGE step succeeded with result %+v", challengeResult)
			break
		}
		logger.Infof("Email choice CHALLENGE step failed with result %+v", challengeResult)
	}
	for {
		fmt.Print("Enter the secret code you received to your email: ")
		bytePassword, _ := term.ReadPassword(syscall.Stdin)
		challengeResult, challengeError := requesterState.ExpressEmailCodeChallenge(string(bytePassword))
		if challengeError != nil {
			logger.Fatalf("Encountered error email code CHALLENGE step: %+v", challengeError)
		}
		if challengeResult.ChallengeStatus == client.ChallengeStatusSuccess {
			logger.Infof("Email code CHALLENGE step succeeded with result %+v", challengeResult)
			break
		}
		logger.Infof("Email code CHALLENGE step failed with result %+v", challengeResult)
	}
}
