package main

import (
	"fmt"
	"github.com/apex/log"
	basic_engine "github.com/zjkmxy/go-ndn/pkg/engine/basic"
	sec "github.com/zjkmxy/go-ndn/pkg/security"
	"go-ndncert/ndncert/client"
	"os"
	"os/signal"
	"syscall"
)

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

	var caPrefix string
	fmt.Print("Enter the Ca Prefix: ")
	requesterState := client.NewRequesterState(caPrefix)
	fmt.Scan(&caPrefix)
	requesterState.ExpressNewInterest(ndnEngine)
	for requesterState.ChallengeStatus == client.ChallengeStatusAfterNewData {
		fmt.Print("Enter the email address you wish to send the secret code to: ")
		fmt.Scan(&emailAddress)
	}
	fmt.Print("Enter the secret code you received from your email: ")

	requesterState := client.NewRequesterState()

	// Wait for keyboard quit signal
	sigChannel := make(chan os.Signal, 1)
	fmt.Print("Start serving ...\n")
	signal.Notify(sigChannel, os.Interrupt, syscall.SIGTERM)
	receivedSig := <-sigChannel
	logger.Infof("Received signal %+v - exiting\n", receivedSig)
}
