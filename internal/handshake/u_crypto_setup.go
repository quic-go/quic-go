package handshake

import (
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/qtls"
	"github.com/quic-go/quic-go/internal/utils"
	"github.com/quic-go/quic-go/internal/wire"
	"github.com/quic-go/quic-go/logging"
	tls "github.com/refraction-networking/utls"
)

// [UQUIC]
// NewUCryptoSetupClient creates a new crypto setup for the client with UTLS
func NewUCryptoSetupClient(
	connID protocol.ConnectionID,
	tp *wire.TransportParameters,
	tlsConf *tls.Config,
	enable0RTT bool,
	rttStats *utils.RTTStats,
	tracer logging.ConnectionTracer,
	logger utils.Logger,
	version protocol.VersionNumber,
	chs *tls.ClientHelloSpec,
) CryptoSetup {
	cs := newCryptoSetup(
		connID,
		tp,
		rttStats,
		tracer,
		logger,
		protocol.PerspectiveClient,
		version,
	)

	tlsConf = tlsConf.Clone()
	tlsConf.MinVersion = tls.VersionTLS13
	quicConf := &qtls.QUICConfig{TLSConfig: tlsConf}
	qtls.SetupConfigForClient(quicConf, cs.marshalDataForSessionState, cs.handleDataFromSessionState)
	cs.tlsConf = tlsConf

	cs.conn = qtls.UQUICClient(quicConf, chs)
	// cs.conn.SetTransportParameters(cs.ourParams.Marshal(protocol.PerspectiveClient)) // [UQUIC] doesn't require this

	return cs
}
