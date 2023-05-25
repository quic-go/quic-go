//go:build go1.21

package qtls

import (
	"crypto/tls"
	"fmt"

	"github.com/quic-go/quic-go/internal/protocol"
)

type (
	QUICConn            = tls.QUICConn
	QUICConfig          = tls.QUICConfig
	QUICEvent           = tls.QUICEvent
	QUICEventKind       = tls.QUICEventKind
	QUICEncryptionLevel = tls.QUICEncryptionLevel
	AlertError          = tls.AlertError
)

const (
	QUICEncryptionLevelInitial     = tls.QUICEncryptionLevelInitial
	QUICEncryptionLevelEarly       = tls.QUICEncryptionLevelEarly
	QUICEncryptionLevelHandshake   = tls.QUICEncryptionLevelHandshake
	QUICEncryptionLevelApplication = tls.QUICEncryptionLevelApplication
)

const (
	QUICNoEvent                     = tls.QUICNoEvent
	QUICSetReadSecret               = tls.QUICSetReadSecret
	QUICSetWriteSecret              = tls.QUICSetWriteSecret
	QUICWriteData                   = tls.QUICWriteData
	QUICTransportParameters         = tls.QUICTransportParameters
	QUICTransportParametersRequired = tls.QUICTransportParametersRequired
	QUICRejectedEarlyData           = tls.QUICRejectedEarlyData
	QUICHandshakeDone               = tls.QUICHandshakeDone
)

func QUICServer(config *QUICConfig) *QUICConn { return tls.QUICServer(config) }
func QUICClient(config *QUICConfig) *QUICConn { return tls.QUICClient(config) }

func SetupConfigForServer(qconf *QUICConfig, _ bool, getData func() []byte, accept0RTT func([]byte) bool) {
	conf := qconf.TLSConfig
	conf = conf.Clone()
	qconf.TLSConfig = conf

	// add callbacks to save transport parameters into the session ticket
	origWrapSession := conf.WrapSession
	conf.WrapSession = func(cs tls.ConnectionState, state *tls.SessionState) ([]byte, error) {
		// Add QUIC transport parameters if this is a 0-RTT packet.
		// TODO(#3853): also save the RTT for non-0-RTT tickets
		if state.EarlyData {
			// At this point, crypto/tls has just called the WrapSession callback.
			// state.Extra is guaranteed to be empty.
			state.Extra = getData()
		}
		if origWrapSession != nil {
			return origWrapSession(cs, state)
		}
		b, err := conf.EncryptTicket(cs, state)
		return b, err
	}
	origUnwrapSession := conf.UnwrapSession
	// UnwrapSession might be called multiple times, as the client can use multiple session tickets.
	// However, using 0-RTT is only possible with the first session ticket.
	// crypto/tls guarantees that this callback is called in the same order as the session ticket in the ClientHello.
	var unwrapCount int
	conf.UnwrapSession = func(identity []byte, connState tls.ConnectionState) (*tls.SessionState, error) {
		unwrapCount++
		var state *tls.SessionState
		var err error
		if origUnwrapSession != nil {
			state, err = origUnwrapSession(identity, connState)
		} else {
			state, err = conf.DecryptTicket(identity, connState)
		}
		if err != nil || state == nil {
			return nil, err
		}
		if state.EarlyData {
			if unwrapCount == 1 { // first session ticket
				state.EarlyData = accept0RTT(state.Extra)
			} else { // subsequent session ticket, can't be used for 0-RTT
				state.EarlyData = false
			}
		}
		return state, nil
	}
}

func SetupConfigForClient(qconf *QUICConfig, getData func() []byte, setData func([]byte)) {
	conf := qconf.TLSConfig
	if conf.ClientSessionCache != nil {
		origCache := conf.ClientSessionCache
		conf.ClientSessionCache = &clientSessionCache{
			wrapped: origCache,
			getData: getData,
			setData: setData,
		}
	}
}

func ToTLSEncryptionLevel(e protocol.EncryptionLevel) tls.QUICEncryptionLevel {
	switch e {
	case protocol.EncryptionInitial:
		return tls.QUICEncryptionLevelInitial
	case protocol.EncryptionHandshake:
		return tls.QUICEncryptionLevelHandshake
	case protocol.Encryption1RTT:
		return tls.QUICEncryptionLevelApplication
	case protocol.Encryption0RTT:
		return tls.QUICEncryptionLevelEarly
	default:
		panic(fmt.Sprintf("unexpected encryption level: %s", e))
	}
}

func FromTLSEncryptionLevel(e tls.QUICEncryptionLevel) protocol.EncryptionLevel {
	switch e {
	case tls.QUICEncryptionLevelInitial:
		return protocol.EncryptionInitial
	case tls.QUICEncryptionLevelHandshake:
		return protocol.EncryptionHandshake
	case tls.QUICEncryptionLevelApplication:
		return protocol.Encryption1RTT
	case tls.QUICEncryptionLevelEarly:
		return protocol.Encryption0RTT
	default:
		panic(fmt.Sprintf("unexpect encryption level: %s", e))
	}
}
