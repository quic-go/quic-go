package quic

import (
	"context"
	"crypto/tls"

	"github.com/quic-go/quic-go/internal/handshake"
	"github.com/quic-go/quic-go/internal/protocol"
)

type qmuxCryptoStreamHandler struct {
	state handshake.ConnectionState
}

var _ cryptoStreamHandler = &qmuxCryptoStreamHandler{}

func newQMuxCryptoStreamHandler(cs tls.ConnectionState) *qmuxCryptoStreamHandler {
	return &qmuxCryptoStreamHandler{state: handshake.ConnectionState{ConnectionState: cs}}
}

func (h *qmuxCryptoStreamHandler) StartHandshake(context.Context) error { return nil }

func (h *qmuxCryptoStreamHandler) ChangeConnectionID(protocol.ConnectionID) {}

func (h *qmuxCryptoStreamHandler) SetLargest1RTTAcked(protocol.PacketNumber) error { return nil }

func (h *qmuxCryptoStreamHandler) SetHandshakeConfirmed() {}

func (h *qmuxCryptoStreamHandler) GetSessionTicket() ([]byte, error) { return nil, nil }

func (h *qmuxCryptoStreamHandler) NextEvent() handshake.Event {
	return handshake.Event{Kind: handshake.EventNoEvent}
}

func (h *qmuxCryptoStreamHandler) DiscardInitialKeys() {}

func (h *qmuxCryptoStreamHandler) HandleMessage([]byte, protocol.EncryptionLevel) error { return nil }

func (h *qmuxCryptoStreamHandler) Close() error { return nil }

func (h *qmuxCryptoStreamHandler) ConnectionState() handshake.ConnectionState { return h.state }
