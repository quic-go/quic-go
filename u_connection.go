package quic

import (
	"context"

	"github.com/quic-go/quic-go/internal/ackhandler"
	"github.com/quic-go/quic-go/internal/handshake"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/utils"
	"github.com/quic-go/quic-go/internal/wire"
	"github.com/quic-go/quic-go/logging"
	tls "github.com/refraction-networking/utls"
)

// [UQUIC]
var newUClientConnection = func(
	conn sendConn,
	runner connRunner,
	destConnID protocol.ConnectionID,
	srcConnID protocol.ConnectionID,
	connIDGenerator ConnectionIDGenerator,
	conf *Config,
	tlsConf *tls.Config,
	initialPacketNumber protocol.PacketNumber,
	enable0RTT bool,
	hasNegotiatedVersion bool,
	tracer logging.ConnectionTracer,
	tracingID uint64,
	logger utils.Logger,
	v protocol.VersionNumber,
	// chs *tls.ClientHelloSpec,
	// initPktNbrLen PacketNumberLen,
	// qfs QUICFrames,
	// udpDatagramMinSize int,
	uSpec *QUICSpec, // [UQUIC]
) quicConn {
	s := &connection{
		conn:                conn,
		config:              conf,
		origDestConnID:      destConnID,
		handshakeDestConnID: destConnID,
		srcConnIDLen:        srcConnID.Len(),
		perspective:         protocol.PerspectiveClient,
		logID:               destConnID.String(),
		logger:              logger,
		tracer:              tracer,
		versionNegotiated:   hasNegotiatedVersion,
		version:             v,
	}
	s.connIDManager = newConnIDManager(
		destConnID,
		func(token protocol.StatelessResetToken) { runner.AddResetToken(token, s) },
		runner.RemoveResetToken,
		s.queueControlFrame,
	)

	s.connIDGenerator = newConnIDGenerator(
		srcConnID,
		nil,
		func(connID protocol.ConnectionID) { runner.Add(connID, s) },
		runner.GetStatelessResetToken,
		runner.Remove,
		runner.Retire,
		runner.ReplaceWithClosed,
		s.queueControlFrame,
		connIDGenerator,
	)
	s.preSetup()
	s.ctx, s.ctxCancel = context.WithCancelCause(context.WithValue(context.Background(), ConnectionTracingKey, tracingID))
	s.sentPacketHandler, s.receivedPacketHandler = ackhandler.NewUAckHandler( // [UQUIC]
		initialPacketNumber,
		getMaxPacketSize(s.conn.RemoteAddr()),
		s.rttStats,
		false, /* has no effect */
		s.perspective,
		s.tracer,
		s.logger,
	)
	// [UQUIC]
	if uSpec.InitialPacketSpec.InitPacketNumberLength != 0 {
		ackhandler.SetInitialPacketNumberLength(s.sentPacketHandler, uSpec.InitialPacketSpec.InitPacketNumberLength)
	}

	s.mtuDiscoverer = newMTUDiscoverer(s.rttStats, getMaxPacketSize(s.conn.RemoteAddr()), s.sentPacketHandler.SetMaxDatagramSize)
	oneRTTStream := newCryptoStream()

	var params *wire.TransportParameters

	if uSpec.ClientHelloSpec != nil {
		// iterate over all Extensions to set the TransportParameters
		var tpSet bool
	FOR_EACH_TLS_EXTENSION:
		for _, ext := range uSpec.ClientHelloSpec.Extensions {
			switch ext := ext.(type) {
			case *tls.QUICTransportParametersExtension:
				params = &wire.TransportParameters{
					InitialSourceConnectionID: srcConnID,
				}
				params.PopulateFromUQUIC(ext.TransportParameters)
				s.connIDManager.SetConnectionIDLimit(params.ActiveConnectionIDLimit)
				tpSet = true
				break FOR_EACH_TLS_EXTENSION
			default:
				continue FOR_EACH_TLS_EXTENSION
			}
		}
		if !tpSet {
			panic("applied ClientHelloSpec must contain a QUICTransportParametersExtension to proceed")
		}
	} else {
		// use default TransportParameters
		params = &wire.TransportParameters{
			InitialMaxStreamDataBidiRemote: protocol.ByteCount(s.config.InitialStreamReceiveWindow),
			InitialMaxStreamDataBidiLocal:  protocol.ByteCount(s.config.InitialStreamReceiveWindow),
			InitialMaxStreamDataUni:        protocol.ByteCount(s.config.InitialStreamReceiveWindow),
			InitialMaxData:                 protocol.ByteCount(s.config.InitialConnectionReceiveWindow),
			MaxIdleTimeout:                 s.config.MaxIdleTimeout,
			MaxBidiStreamNum:               protocol.StreamNum(s.config.MaxIncomingStreams),
			MaxUniStreamNum:                protocol.StreamNum(s.config.MaxIncomingUniStreams),
			MaxAckDelay:                    protocol.MaxAckDelayInclGranularity,
			AckDelayExponent:               protocol.AckDelayExponent,
			DisableActiveMigration:         true,
			// For interoperability with quic-go versions before May 2023, this value must be set to a value
			// different from protocol.DefaultActiveConnectionIDLimit.
			// If set to the default value, it will be omitted from the transport parameters, which will make
			// old quic-go versions interpret it as 0, instead of the default value of 2.
			// See https://github.com/quic-go/quic-go/pull/3806.
			ActiveConnectionIDLimit:   protocol.MaxActiveConnectionIDs,
			InitialSourceConnectionID: srcConnID,
		}
		if s.config.EnableDatagrams {
			params.MaxDatagramFrameSize = protocol.MaxDatagramFrameSize
		} else {
			params.MaxDatagramFrameSize = protocol.InvalidByteCount
		}
	}

	if s.tracer != nil {
		s.tracer.SentTransportParameters(params)
	}
	cs := handshake.NewUCryptoSetupClient(
		destConnID,
		params,
		tlsConf,
		enable0RTT,
		s.rttStats,
		tracer,
		logger,
		s.version,
		uSpec.ClientHelloSpec,
	)
	s.cryptoStreamHandler = cs
	s.cryptoStreamManager = newCryptoStreamManager(cs, s.initialStream, s.handshakeStream, oneRTTStream)
	s.unpacker = newPacketUnpacker(cs, s.srcConnIDLen)
	s.packer = newUPacketPacker(
		newPacketPacker(srcConnID, s.connIDManager.Get, s.initialStream, s.handshakeStream, s.sentPacketHandler, s.retransmissionQueue, cs, s.framer, s.receivedPacketHandler, s.datagramQueue, s.perspective),
		uSpec,
	)
	if len(tlsConf.ServerName) > 0 {
		s.tokenStoreKey = tlsConf.ServerName
	} else {
		s.tokenStoreKey = conn.RemoteAddr().String()
	}
	if s.config.TokenStore != nil {
		if token := s.config.TokenStore.Pop(s.tokenStoreKey); token != nil {
			s.packer.SetToken(token.data)
		}
	}
	return s
}
