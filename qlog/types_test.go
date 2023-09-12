package qlog

import (
	"go/ast"
	"go/parser"
	gotoken "go/token"
	"path"
	"runtime"
	"strconv"

	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/qerr"
	"github.com/quic-go/quic-go/logging"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Types", func() {
	It("has a string representation for the owner", func() {
		Expect(ownerLocal.String()).To(Equal("local"))
		Expect(ownerRemote.String()).To(Equal("remote"))
	})

	It("has a string representation for the category", func() {
		Expect(categoryConnectivity.String()).To(Equal("connectivity"))
		Expect(categoryTransport.String()).To(Equal("transport"))
		Expect(categoryRecovery.String()).To(Equal("recovery"))
		Expect(categorySecurity.String()).To(Equal("security"))
	})

	It("has a string representation for the packet type", func() {
		Expect(packetType(logging.PacketTypeInitial).String()).To(Equal("initial"))
		Expect(packetType(logging.PacketTypeHandshake).String()).To(Equal("handshake"))
		Expect(packetType(logging.PacketType0RTT).String()).To(Equal("0RTT"))
		Expect(packetType(logging.PacketType1RTT).String()).To(Equal("1RTT"))
		Expect(packetType(logging.PacketTypeStatelessReset).String()).To(Equal("stateless_reset"))
		Expect(packetType(logging.PacketTypeRetry).String()).To(Equal("retry"))
		Expect(packetType(logging.PacketTypeVersionNegotiation).String()).To(Equal("version_negotiation"))
		Expect(packetType(logging.PacketTypeNotDetermined).String()).To(BeEmpty())
	})

	It("has a string representation for the packet drop reason", func() {
		Expect(packetDropReason(logging.PacketDropKeyUnavailable).String()).To(Equal("key_unavailable"))
		Expect(packetDropReason(logging.PacketDropUnknownConnectionID).String()).To(Equal("unknown_connection_id"))
		Expect(packetDropReason(logging.PacketDropHeaderParseError).String()).To(Equal("header_parse_error"))
		Expect(packetDropReason(logging.PacketDropPayloadDecryptError).String()).To(Equal("payload_decrypt_error"))
		Expect(packetDropReason(logging.PacketDropProtocolViolation).String()).To(Equal("protocol_violation"))
		Expect(packetDropReason(logging.PacketDropDOSPrevention).String()).To(Equal("dos_prevention"))
		Expect(packetDropReason(logging.PacketDropUnsupportedVersion).String()).To(Equal("unsupported_version"))
		Expect(packetDropReason(logging.PacketDropUnexpectedPacket).String()).To(Equal("unexpected_packet"))
		Expect(packetDropReason(logging.PacketDropUnexpectedSourceConnectionID).String()).To(Equal("unexpected_source_connection_id"))
		Expect(packetDropReason(logging.PacketDropUnexpectedVersion).String()).To(Equal("unexpected_version"))
	})

	It("has a string representation for the timer type", func() {
		Expect(timerType(logging.TimerTypeACK).String()).To(Equal("ack"))
		Expect(timerType(logging.TimerTypePTO).String()).To(Equal("pto"))
	})

	It("has a string representation for the key type", func() {
		Expect(encLevelToKeyType(protocol.EncryptionInitial, protocol.PerspectiveClient).String()).To(Equal("client_initial_secret"))
		Expect(encLevelToKeyType(protocol.EncryptionInitial, protocol.PerspectiveServer).String()).To(Equal("server_initial_secret"))
		Expect(encLevelToKeyType(protocol.EncryptionHandshake, protocol.PerspectiveClient).String()).To(Equal("client_handshake_secret"))
		Expect(encLevelToKeyType(protocol.EncryptionHandshake, protocol.PerspectiveServer).String()).To(Equal("server_handshake_secret"))
		Expect(encLevelToKeyType(protocol.Encryption0RTT, protocol.PerspectiveClient).String()).To(Equal("client_0rtt_secret"))
		Expect(encLevelToKeyType(protocol.Encryption0RTT, protocol.PerspectiveServer).String()).To(Equal("server_0rtt_secret"))
		Expect(encLevelToKeyType(protocol.Encryption1RTT, protocol.PerspectiveClient).String()).To(Equal("client_1rtt_secret"))
		Expect(encLevelToKeyType(protocol.Encryption1RTT, protocol.PerspectiveServer).String()).To(Equal("server_1rtt_secret"))
	})

	It("has a string representation for the key update trigger", func() {
		Expect(keyUpdateTLS.String()).To(Equal("tls"))
		Expect(keyUpdateRemote.String()).To(Equal("remote_update"))
		Expect(keyUpdateLocal.String()).To(Equal("local_update"))
	})

	It("tells the packet number space from the encryption level", func() {
		Expect(encLevelToPacketNumberSpace(protocol.EncryptionInitial)).To(Equal("initial"))
		Expect(encLevelToPacketNumberSpace(protocol.EncryptionHandshake)).To(Equal("handshake"))
		Expect(encLevelToPacketNumberSpace(protocol.Encryption0RTT)).To(Equal("application_data"))
		Expect(encLevelToPacketNumberSpace(protocol.Encryption1RTT)).To(Equal("application_data"))
	})

	Context("transport errors", func() {
		It("has a string representation for every error code", func() {
			// We parse the error code file, extract all constants, and verify that
			// each of them has a string version. Go FTW!
			_, thisfile, _, ok := runtime.Caller(0)
			if !ok {
				panic("Failed to get current frame")
			}
			filename := path.Join(path.Dir(thisfile), "../internal/qerr/error_codes.go")
			fileAst, err := parser.ParseFile(gotoken.NewFileSet(), filename, nil, 0)
			Expect(err).NotTo(HaveOccurred())
			constSpecs := fileAst.Decls[2].(*ast.GenDecl).Specs
			Expect(len(constSpecs)).To(BeNumerically(">", 4)) // at time of writing
			for _, c := range constSpecs {
				valString := c.(*ast.ValueSpec).Values[0].(*ast.BasicLit).Value
				val, err := strconv.ParseInt(valString, 0, 64)
				Expect(err).NotTo(HaveOccurred())
				Expect(transportError(val).String()).ToNot(BeEmpty())
			}
		})

		It("has a string representation for transport errors", func() {
			Expect(transportError(qerr.NoError).String()).To(Equal("no_error"))
			Expect(transportError(qerr.InternalError).String()).To(Equal("internal_error"))
			Expect(transportError(qerr.ConnectionRefused).String()).To(Equal("connection_refused"))
			Expect(transportError(qerr.FlowControlError).String()).To(Equal("flow_control_error"))
			Expect(transportError(qerr.StreamLimitError).String()).To(Equal("stream_limit_error"))
			Expect(transportError(qerr.StreamStateError).String()).To(Equal("stream_state_error"))
			Expect(transportError(qerr.FrameEncodingError).String()).To(Equal("frame_encoding_error"))
			Expect(transportError(qerr.ConnectionIDLimitError).String()).To(Equal("connection_id_limit_error"))
			Expect(transportError(qerr.ProtocolViolation).String()).To(Equal("protocol_violation"))
			Expect(transportError(qerr.InvalidToken).String()).To(Equal("invalid_token"))
			Expect(transportError(qerr.ApplicationErrorErrorCode).String()).To(Equal("application_error"))
			Expect(transportError(qerr.CryptoBufferExceeded).String()).To(Equal("crypto_buffer_exceeded"))
			Expect(transportError(qerr.NoViablePathError).String()).To(Equal("no_viable_path"))
			Expect(transportError(1337).String()).To(BeEmpty())
		})
	})

	It("has a string representation for congestion state updates", func() {
		Expect(congestionState(logging.CongestionStateSlowStart).String()).To(Equal("slow_start"))
		Expect(congestionState(logging.CongestionStateCongestionAvoidance).String()).To(Equal("congestion_avoidance"))
		Expect(congestionState(logging.CongestionStateApplicationLimited).String()).To(Equal("application_limited"))
		Expect(congestionState(logging.CongestionStateRecovery).String()).To(Equal("recovery"))
	})

	It("has a string representation for the ECN bits", func() {
		Expect(ecn(logging.ECT0).String()).To(Equal("ECT(0)"))
		Expect(ecn(logging.ECT1).String()).To(Equal("ECT(1)"))
		Expect(ecn(logging.ECNCE).String()).To(Equal("CE"))
		Expect(ecn(logging.ECTNot).String()).To(Equal("Not-ECT"))
		Expect(ecn(42).String()).To(Equal("unknown ECN"))
	})

	It("has a string representation for the ECN state", func() {
		Expect(ecnState(logging.ECNStateTesting).String()).To(Equal("testing"))
		Expect(ecnState(logging.ECNStateUnknown).String()).To(Equal("unknown"))
		Expect(ecnState(logging.ECNStateFailed).String()).To(Equal("failed"))
		Expect(ecnState(logging.ECNStateCapable).String()).To(Equal("capable"))
		Expect(ecnState(42).String()).To(Equal("unknown ECN state"))
	})

	It("has a string representation for the ECN state trigger", func() {
		Expect(ecnStateTrigger(logging.ECNTriggerNoTrigger).String()).To(Equal(""))
		Expect(ecnStateTrigger(logging.ECNFailedNoECNCounts).String()).To(Equal("ACK doesn't contain ECN marks"))
		Expect(ecnStateTrigger(logging.ECNFailedDecreasedECNCounts).String()).To(Equal("ACK decreases ECN counts"))
		Expect(ecnStateTrigger(logging.ECNFailedLostAllTestingPackets).String()).To(Equal("all ECN testing packets declared lost"))
		Expect(ecnStateTrigger(logging.ECNFailedMoreECNCountsThanSent).String()).To(Equal("ACK contains more ECN counts than ECN-marked packets sent"))
		Expect(ecnStateTrigger(logging.ECNFailedTooFewECNCounts).String()).To(Equal("ACK contains fewer new ECN counts than acknowledged ECN-marked packets"))
		Expect(ecnStateTrigger(logging.ECNFailedManglingDetected).String()).To(Equal("ECN mangling detected"))
		Expect(ecnStateTrigger(42).String()).To(Equal("unknown ECN state trigger"))
	})
})
