//go:build go1.21 && utls

package qtls

import (
	"bytes"
	"fmt"

	gotls "crypto/tls"

	"gitlab.com/go-extension/tls"

	_ "unsafe"

	"github.com/quic-go/quic-go/internal/protocol"
)

type (
	Conn               = tls.Conn
	Config             = tls.Config
	ConnectionState    = tls.ConnectionState
	SessionState       = tls.SessionState
	ClientSessionCache = tls.ClientSessionCache
	ClientSessionState = tls.ClientSessionState
	Certificate        = tls.Certificate
	CurveID            = tls.CurveID
	ClientHelloInfo    = tls.ClientHelloInfo
	ClientAuthType     = tls.ClientAuthType
)

type (
	QUICConn                 = tls.QUICConn
	QUICConfig               = tls.QUICConfig
	QUICEvent                = tls.QUICEvent
	QUICEventKind            = tls.QUICEventKind
	QUICEncryptionLevel      = tls.QUICEncryptionLevel
	QUICSessionTicketOptions = tls.QUICSessionTicketOptions
	AlertError               = tls.AlertError
)

var (
	CipherSuiteName          = tls.CipherSuiteName
	NewResumptionState       = tls.NewResumptionState
	LoadX509KeyPair          = tls.LoadX509KeyPair
	X509KeyPair              = tls.X509KeyPair
	NewLRUClientSessionCache = tls.NewLRUClientSessionCache
	Listen                   = tls.Listen
	Dial                     = tls.Dial
)

const (
	VersionTLS12 = tls.VersionTLS12
	VersionTLS13 = tls.VersionTLS13

	TLS_AES_128_GCM_SHA256       = tls.TLS_AES_128_GCM_SHA256       // nolint: stylecheck
	TLS_AES_256_GCM_SHA384       = tls.TLS_AES_256_GCM_SHA384       // nolint: stylecheck
	TLS_CHACHA20_POLY1305_SHA256 = tls.TLS_CHACHA20_POLY1305_SHA256 // nolint: stylecheck

	CurveP256 = tls.CurveP256
	CurveP384 = tls.CurveP384
	CurveP521 = tls.CurveP521
	X25519    = tls.X25519

	NoClientCert               = tls.NoClientCert
	RequestClientCert          = tls.RequestClientCert
	RequireAnyClientCert       = tls.RequireAnyClientCert
	VerifyClientCertIfGiven    = tls.VerifyClientCertIfGiven
	RequireAndVerifyClientCert = tls.RequireAndVerifyClientCert
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

//go:linkname quicMaxEarlyData gitlab.com/go-extension/tls.quicMaxEarlyData
var quicMaxEarlyData uint32

func QUICServer(config *QUICConfig) *QUICConn { return tls.QUICServer(config) }
func QUICClient(config *QUICConfig) *QUICConn { return tls.QUICClient(config) }

func SetupConfigForServer(qconf *QUICConfig, _ bool, getData func() []byte, accept0RTT func([]byte) bool) {
	conf := qconf.TLSConfig

	// Workaround for https://github.com/golang/go/issues/60506.
	// This initializes the session tickets _before_ cloning the config.
	_, _ = conf.DecryptTicket(nil, tls.ConnectionState{})

	conf = conf.Clone()
	conf.MinVersion = tls.VersionTLS13
	qconf.TLSConfig = conf

	// add callbacks to save transport parameters into the session ticket
	origWrapSession := conf.WrapSession
	conf.WrapSession = func(cs tls.ConnectionState, state *tls.SessionState) ([]byte, error) {
		// Add QUIC transport parameters if this is a 0-RTT packet.
		// TODO(#3853): also save the RTT for non-0-RTT tickets
		if state.MaxEarlyData > 0 {
			state.Extra = append(state.Extra, addExtraPrefix(getData()))
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
		if state.MaxEarlyData > 0 {
			extra := findExtraData(state.Extra)
			if unwrapCount == 1 && extra != nil { // first session ticket
				if accept0RTT(extra) {
					state.MaxEarlyData = quicMaxEarlyData
				} else {
					state.MaxEarlyData = 0
				}
			} else { // subsequent session ticket, can't be used for 0-RTT
				state.MaxEarlyData = 0
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

const extraPrefix = "quic-go1"

func addExtraPrefix(b []byte) []byte {
	return append([]byte(extraPrefix), b...)
}

func findExtraData(extras [][]byte) []byte {
	prefix := []byte(extraPrefix)
	for _, extra := range extras {
		if len(extra) < len(prefix) || !bytes.Equal(prefix, extra[:len(prefix)]) {
			continue
		}
		return extra[len(prefix):]
	}
	return nil
}

func SendSessionTicket(c *QUICConn, allow0RTT bool) error {
	return c.SendSessionTicket(tls.QUICSessionTicketOptions{
		EarlyData: allow0RTT,
	})
}

func ToConnectionState(cs ConnectionState) gotls.ConnectionState {
	return cs.Compatible()
}
