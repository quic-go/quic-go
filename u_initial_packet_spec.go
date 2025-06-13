package quic

import (
	"crypto/rand"
	"github.com/Noooste/uquic-go/internal/protocol"
)

type InitialPacketSpec struct {
	// SrcConnIDLength specifies how many bytes should the SrcConnID be
	SrcConnIDLength int

	// DestConnIDLength specifies how many bytes should the DestConnID be
	DestConnIDLength int

	// InitPacketNumberLength specifies how many bytes should the InitPacketNumber
	// be interpreted as. It is usually 1 or 2 bytes. If unset, UQUIC will use the
	// default algorithm to compute the length which is at least 2 bytes.
	InitPacketNumberLength protocol.PacketNumberLen

	// InitPacketNumber is the packet number of the first Initial packet. Following
	// Initial packets, if any, will increment the Packet Number accordingly.
	InitPacketNumber uint64 // [UQUIC]

	// TokenStore is used to store and retrieve tokens. If set, will override the
	// one set in the Config.
	TokenStore TokenStore

	// If ClientTokenLength is set when TokenStore is not set, a dummy TokenStore
	// will be created to randomly generate tokens of the specified length for
	// Pop() calls with any key and silently drop any Put() calls.
	//
	// However, the tokens will not be stored anywhere and are expected to be
	// invalid since not assigned by the server.
	ClientTokenLength int

	// FrameBuilder specifies how the frames should be encapsulated for the first Initial
	// packet.
	//
	// If nil, there will be only one single Crypto frame in the first Initial packet.
	FrameBuilder QUICFrameBuilder
}

func (ps *InitialPacketSpec) UpdateConfig(conf *Config) {
	conf.TokenStore = ps.getTokenStore()
}

func (ps *InitialPacketSpec) getTokenStore() TokenStore {
	if ps.TokenStore != nil {
		return ps.TokenStore
	}

	if ps.ClientTokenLength > 0 {
		return &dummyTokenStore{
			tokenLength: ps.ClientTokenLength,
		}
	}

	return nil
}

type dummyTokenStore struct {
	tokenLength int
}

func (d *dummyTokenStore) Pop(key string) (token *ClientToken) {
	var data []byte = make([]byte, d.tokenLength)
	rand.Read(data)

	return &ClientToken{
		data: data,
	}
}

func (d *dummyTokenStore) Put(_ string, _ *ClientToken) {
	// Do nothing
}
