package qlog

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path"
	"runtime"
	"strconv"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/qerr"

	. "github.com/onsi/ginkgo"
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
		Expect(PacketTypeInitial.String()).To(Equal("initial"))
		Expect(PacketTypeHandshake.String()).To(Equal("handshake"))
		Expect(PacketType0RTT.String()).To(Equal("0RTT"))
		Expect(PacketType1RTT.String()).To(Equal("1RTT"))
		Expect(PacketTypeStatelessReset.String()).To(Equal("stateless_reset"))
		Expect(PacketTypeRetry.String()).To(Equal("retry"))
		Expect(PacketTypeVersionNegotiation.String()).To(Equal("version_negotiation"))
		Expect(PacketTypeNotDetermined.String()).To(BeEmpty())
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

	It("has a string representation for the packet drop reason", func() {
		Expect(PacketDropKeyUnavailable.String()).To(Equal("key_unavailable"))
		Expect(PacketDropUnknownConnectionID.String()).To(Equal("unknown_connection_id"))
		Expect(PacketDropHeaderParseError.String()).To(Equal("header_parse_error"))
		Expect(PacketDropPayloadDecryptError.String()).To(Equal("payload_decrypt_error"))
		Expect(PacketDropProtocolViolation.String()).To(Equal("protocol_violation"))
		Expect(PacketDropDOSPrevention.String()).To(Equal("dos_prevention"))
		Expect(PacketDropUnsupportedVersion.String()).To(Equal("unsupported_version"))
		Expect(PacketDropUnexpectedPacket.String()).To(Equal("unexpected_packet"))
		Expect(PacketDropUnexpectedSourceConnectionID.String()).To(Equal("unexpected_source_connection_id"))
		Expect(PacketDropUnexpectedVersion.String()).To(Equal("unexpected_version"))
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
			fileAst, err := parser.ParseFile(token.NewFileSet(), filename, nil, 0)
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
			Expect(transportError(qerr.ServerBusy).String()).To(Equal("server_busy"))
			Expect(transportError(qerr.FlowControlError).String()).To(Equal("flow_control_error"))
			Expect(transportError(qerr.StreamLimitError).String()).To(Equal("stream_limit_error"))
			Expect(transportError(qerr.StreamStateError).String()).To(Equal("stream_state_error"))
			Expect(transportError(qerr.FrameEncodingError).String()).To(Equal("frame_encoding_error"))
			Expect(transportError(qerr.ConnectionIDLimitError).String()).To(Equal("connection_id_limit_error"))
			Expect(transportError(qerr.ProtocolViolation).String()).To(Equal("protocol_violation"))
			Expect(transportError(qerr.InvalidToken).String()).To(Equal("invalid_token"))
			Expect(transportError(qerr.ApplicationError).String()).To(Equal("application_error"))
			Expect(transportError(qerr.CryptoBufferExceeded).String()).To(Equal("crypto_buffer_exceeded"))
			Expect(transportError(1337).String()).To(BeEmpty())
		})
	})

	It("has a string representation for the timer type", func() {
		Expect(TimerTypeACK.String()).To(Equal("ack"))
		Expect(TimerTypePTO.String()).To(Equal("pto"))
	})

	It("has a string representation for the close reason", func() {
		Expect(CloseReasonHandshakeTimeout.String()).To(Equal("handshake_timeout"))
		Expect(CloseReasonIdleTimeout.String()).To(Equal("idle_timeout"))
	})
})
