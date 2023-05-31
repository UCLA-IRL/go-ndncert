package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"github.com/apex/log"
	enc "github.com/zjkmxy/go-ndn/pkg/encoding"
	basic_engine "github.com/zjkmxy/go-ndn/pkg/engine/basic"
	"github.com/zjkmxy/go-ndn/pkg/ndn"
	sec "github.com/zjkmxy/go-ndn/pkg/security"
	"go-ndncert/email"
	"go-ndncert/ndncert/server"
	"math/big"
	"os"
	"os/signal"
	"syscall"
	"time"
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

	// Generate ECDSA key used for ca's identity
	certKey, certKeyError := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if certKeyError != nil {
		logger.Error("Failed to generate certificate private key using ecdsa")
		return
	}

	// Set up CaState
	caCert := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Second * time.Duration(86400)),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		SignatureAlgorithm:    x509.ECDSAWithSHA256,
		BasicConstraintsValid: true,
	}
	caState, caStateSetupError := server.NewCaState("/ndn/edu/ucla", "A really cool ndncert CA server", 31556926, caCert, nil, certKey, smtpModule)
	if caStateSetupError != nil {
		logger.Fatalf("Error encountered setting up CA State: %+v", caStateSetupError)
	}

	// Serve indefinitely
	serveError := caState.Serve(ndnEngine)
	if serveError != nil {
		logger.Fatalf("Error encountered while attempting to serve: %+v", serveError)
	}

	// Wait for keyboard quit signal
	sigChannel := make(chan os.Signal, 1)
	fmt.Print("Start serving ...\n")
	signal.Notify(sigChannel, os.Interrupt, syscall.SIGTERM)
	receivedSig := <-sigChannel
	logger.Infof("Received signal %+v - exiting\n", receivedSig)
}
