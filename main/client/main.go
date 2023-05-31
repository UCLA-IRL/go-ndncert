package main

import (
	"fmt"
	"github.com/apex/log"
	enc "github.com/zjkmxy/go-ndn/pkg/encoding"
	basic_engine "github.com/zjkmxy/go-ndn/pkg/engine/basic"
	"github.com/zjkmxy/go-ndn/pkg/ndn"
	sec "github.com/zjkmxy/go-ndn/pkg/security"
	"go-ndncert/ndncert/client"
	"golang.org/x/term"
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

	requesterState, _ := client.NewRequesterState("client", "/ndn/edu/ucla", ndnEngine, ndnTimer)
	requesterState.ExpressNewInterest(time.Hour)
	requesterState.ExpressEmailChoiceChallenge("ricky99.guo@gmail.com")

	fmt.Print("Enter the secret code you received to your email: ")
	bytePassword, _ := term.ReadPassword(syscall.Stdin)
	requesterState.ExpressEmailCodeChallenge(string(bytePassword))
}
