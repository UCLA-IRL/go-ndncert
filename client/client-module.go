package client

import (
	"fmt"
	enc "github.com/zjkmxy/go-ndn/pkg/encoding"
	"github.com/zjkmxy/go-ndn/pkg/ndn/spec_2022"
	"go-ndncert/crypto"
	"go-ndncert/schemaold"
)

type Client struct {
	ecdhState crypto.ECDHState
}

func ExpressProfileInterest(c *Client) spec_2022.Interest {
	// TODO: Form CA Profile Interest packet
	return spec_2022.Interest{}
}

func ExpressNewInterest(c *Client /* KEY_TYPE_HERE,*/, caPrefix string) spec_2022.Interest {
	// TODO: Form New Interest packet
	c.ecdhState = crypto.ECDHState{}
	c.ecdhState.GenerateKeyPair()
	selfSignedCertificate, _ := enc.NameFromStr("/%s/")
	appParams := schemaold.CmdNewInt{
		EcdhPub: c.ecdhState.PublicKey.Bytes(),
	}
	intName, _ := enc.NameFromStr(fmt.Sprintf("/%s/CA/NEW/params-sha256=%x", caPrefix, appParamsDigest))

	return spec_2022.Interest{}
}

func ExpressChallengeInterest(c *Client) spec_2022.Interest {
	// TODO: Form Challenge Interest packet
	return spec_2022.Interest{}
}

func NewClient() *Client {
	return &Client{}
}
