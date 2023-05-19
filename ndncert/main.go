package ndncert

import (
	"fmt"
	"github.com/apex/log"
	enc "github.com/zjkmxy/go-ndn/pkg/encoding"
	basic_engine "github.com/zjkmxy/go-ndn/pkg/engine/basic"
	"github.com/zjkmxy/go-ndn/pkg/ndn"
	"github.com/zjkmxy/go-ndn/pkg/schema"
	sec "github.com/zjkmxy/go-ndn/pkg/security"
	"os"
	"os/signal"
	"syscall"
	"time"
)

const SchemaJson = `{
  "nodes": {
    "/": {
      "type": "RdrNode",
      "attrs": {
        "MetaFreshness": 10,
        "MaxRetriesForMeta": 2,
        "MetaLifetime": 6000,
        "Lifetime": 6000,
        "Freshness": 3153600000000,
        "ValidDuration": 3153600000000,
        "SegmentSize": 80,
        "MaxRetriesOnFailure": 3,
        "Pipeline": "SinglePacket"
      }
    }
  },
  "policies": [
    {
      "type": "Sha256Signer",
      "path": "/32=metadata/<v=versionNumber>/seg=0"
    },
    {
      "type": "Sha256Signer",
      "path": "/32=metadata"
    },
    {
      "type": "Sha256Signer",
      "path": "/<v=versionNumber>/<seg=segmentNumber>"
    },
    {
      "type": "MemStorage",
      "path": "/",
      "attrs": {}
    }
  ]
}`

func passAll(enc.Name, enc.Wire, ndn.Signature) bool {
	return true
}

func main() {
	log.SetLevel(log.DebugLevel)
	logger := log.WithField("module", "main")

	caName, _ := enc.NameFromStr("/ndn/edu/ucla")
	caInfo := "A Cool NDN CA"
	maxCertValidityPeriod := 86400

	// Setup CA State
	caState := &CaState{
		CaCert:                       enc.Buffer{},
		CaInfo:                       caInfo,
		CaPrefix:                     caName.String(),
		MaxCertValidityPeriod:        time.Duration(maxCertValidityPeriod) * time.Second, // One day in seconds
		ChallengeRequestStateMapping: make(map[[8]byte]*ChallengeRequestState),
	}

	// Setup CA Profile to Serve
	caProfile := &CaProfile{
		CaPrefix:       caName,
		CaInfo:         caInfo,
		ParameterKey:   nil,
		MaxValidPeriod: 0,
		CaCertificate:  nil,
	}

	// Setup schema tree
	tree := schema.CreateFromJson(SchemaJson, map[string]any{})

	// Start engine
	timer := basic_engine.NewTimer()
	face := basic_engine.NewStreamFace("unix", "/var/run/nfd.sock", true)
	app := basic_engine.NewEngine(face, timer, sec.NewSha256IntSigner(timer), passAll)
	err := app.Start()
	if err != nil {
		logger.Fatalf("Unable to start engine: %+v", err)
		return
	}
	defer app.Shutdown()

	// Attach schema
	prefix, _ := enc.NameFromStr("/prefix/CA/INFO")
	err = tree.Attach(prefix, app)
	if err != nil {
		logger.Fatalf("Unable to attach the schema to the engine: %+v", err)
		return
	}
	defer tree.Detach()

	// Produce data
	mNode := tree.Root().Apply(enc.Matching{})
	ver := mNode.Call("Provide", enc.Wire{caProfile.Encode().Join()})
	fmt.Printf("Generated packet with version= %d\n", ver)

	newPrefix, _ := enc.NameFromStr("/prefix/CA/NEW")
	challengePrefix, _ := enc.NameFromStr("/prefix/CA/CHALLENGE")
	app.AttachHandler(newPrefix, func(interest ndn.Interest, rawInterest enc.Wire, sigCovered enc.Wire, reply ndn.ReplyFunc, deadline time.Time) {
		OnNew(caState, interest, rawInterest, sigCovered, reply, deadline)
	})
	app.AttachHandler(challengePrefix, func(interest ndn.Interest, rawInterest enc.Wire, sigCovered enc.Wire, reply ndn.ReplyFunc, deadline time.Time) {
		OnChallenge(caState, interest, rawInterest, sigCovered, reply, deadline)
	})

	// Wait for keyboard quit signal
	sigChannel := make(chan os.Signal, 1)
	fmt.Print("Start serving ...\n")
	signal.Notify(sigChannel, os.Interrupt, syscall.SIGTERM)
	receivedSig := <-sigChannel
	logger.Infof("Received signal %+v - exiting\n", receivedSig)
}
