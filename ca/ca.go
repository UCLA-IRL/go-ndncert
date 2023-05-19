package ca

import (
	enc "github.com/zjkmxy/go-ndn/pkg/encoding"
	"github.com/zjkmxy/go-ndn/pkg/schema"
)

type RequestStateStorage struct {
	requestStateMapping map[[8]byte]*RequestState
}

type CaNode struct {
	schema.BaseNodeImpl

	ownPrefix           enc.Name // The Ca's own prefix.
	requestStateStorage RequestStateStorage
}

func CreateCaNode(node *schema.Node) schema.NodeImpl {
	caNode := &CaNode{
		BaseNodeImpl: schema.BaseNodeImpl{
			Node:        node,
			OnAttachEvt: &schema.EventTarget{},
			OnDetachEvt: &schema.EventTarget{},
		},
	}

	path, _ := enc.NamePatternFromStr("")
}
