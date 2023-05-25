package main

import (
	"fmt"
	"github.com/apex/log"
	enc "github.com/zjkmxy/go-ndn/pkg/encoding"
	basic_engine "github.com/zjkmxy/go-ndn/pkg/engine/basic"
	"github.com/zjkmxy/go-ndn/pkg/ndn"
	sec "github.com/zjkmxy/go-ndn/pkg/security"
	"go-ndncert/email"
	"go-ndncert/ndncert/server"
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

	// Set up SmtpModule
	smtpModule, smtpModuleSetupError := email.NewSmtpModule("../../config/smtp.yml")
	if smtpModuleSetupError != nil {
		logger.Fatalf("Error encountered setting up SMTP module: %+v", smtpModuleSetupError)
	}

	// Set up CaState
	caState, caStateSetupError := server.NewCaState("../../config/ca.yml", smtpModule)
	if caStateSetupError != nil {
		logger.Fatalf("Error encountered setting up CA State: %+v", caStateSetupError)
	}

	// Serve indefinitely
	caState.Serve(ndnEngine)

	// Wait for keyboard quit signal
	sigChannel := make(chan os.Signal, 1)
	fmt.Print("Start serving ...\n")
	signal.Notify(sigChannel, os.Interrupt, syscall.SIGTERM)
	receivedSig := <-sigChannel
	logger.Infof("Received signal %+v - exiting\n", receivedSig)
}
