package main

import (
	"fmt"
	"github.com/apex/log"
	enc "github.com/zjkmxy/go-ndn/pkg/encoding"
	basic_engine "github.com/zjkmxy/go-ndn/pkg/engine/basic"
	"github.com/zjkmxy/go-ndn/pkg/ndn"
	sec "github.com/zjkmxy/go-ndn/pkg/security"
	"go-ndncert/ndncert/client"
	"os"
	"os/signal"
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
		return
	}
	defer ndnEngine.Shutdown()

	infoWire, err := client.ExpressInfoInterest(ndnEngine, "/ndn/edu/ucla")
	if err != nil {
		fmt.Print(err.Error())
	} else {
		fmt.Print(infoWire)
	}
	//requesterState := client.NewRequesterState("/ndn/edu/ucla")
	//requesterState.ExpressNewInterest(ndnEngine)

	// Prompt client for the email address to send the secret code to
	//for requesterState.ChallengeStatus == client.ChallengeStatusAfterNewData {
	//	var emailAddress string
	//	fmt.Print("Enter the email address you wish to send the secret code to: ")
	//	fmt.Scan(&emailAddress)
	//	requesterState.ExpressEmailChoiceChallenge(ndnEngine, emailAddress)
	//}

	// Prompt client for the secret code from the email
	//fmt.Print("Enter the secret code you received from your email: ")
	//_ := client.NewRequesterState(/*)*/

	// Wait for keyboard quit signal
	sigChannel := make(chan os.Signal, 1)
	fmt.Print("Start serving ...\n")
	signal.Notify(sigChannel, os.Interrupt, syscall.SIGTERM)
	receivedSig := <-sigChannel
	logger.Infof("Received signal %+v - exiting\n", receivedSig)
}
