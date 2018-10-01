package quic

import (
	"fmt"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/wire"
)

type cryptoDataHandler interface {
	HandleData([]byte, protocol.EncryptionLevel) error
}

type cryptoStreamManager struct {
	cryptoHandler cryptoDataHandler

	initialStream   cryptoStream
	handshakeStream cryptoStream
}

func newCryptoStreamManager(
	cryptoHandler cryptoDataHandler,
	initialStream cryptoStream,
	handshakeStream cryptoStream,
) *cryptoStreamManager {
	return &cryptoStreamManager{
		cryptoHandler:   cryptoHandler,
		initialStream:   initialStream,
		handshakeStream: handshakeStream,
	}
}

func (m *cryptoStreamManager) HandleCryptoFrame(frame *wire.CryptoFrame, encLevel protocol.EncryptionLevel) error {
	var str cryptoStream
	switch encLevel {
	case protocol.EncryptionInitial:
		str = m.initialStream
	case protocol.EncryptionHandshake:
		str = m.handshakeStream
	default:
		return fmt.Errorf("received CRYPTO frame with unexpected encryption level: %s", encLevel)
	}
	if err := str.HandleCryptoFrame(frame); err != nil {
		return err
	}
	for {
		data := str.GetCryptoData()
		if data == nil {
			return nil
		}
		if err := m.cryptoHandler.HandleData(data, encLevel); err != nil {
			return err
		}
	}
}
