package quic

import (
	"bytes"
	"io"

	"github.com/bifurcation/mint"
	"github.com/lucas-clemente/quic-go/internal/crypto"
	"github.com/lucas-clemente/quic-go/internal/handshake"
	"github.com/lucas-clemente/quic-go/internal/mocks"
	"github.com/lucas-clemente/quic-go/internal/mocks/handshake"
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/testdata"
	"github.com/lucas-clemente/quic-go/internal/wire"
	"github.com/lucas-clemente/quic-go/qerr"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Stateless TLS handling", func() {
	var (
		conn        *mockPacketConn
		server      *serverTLS
		sessionChan <-chan packetHandler
		mintTLS     *mockhandshake.MockMintTLS
		extHandler  *mocks.MockTLSExtensionHandler
		mintReply   io.Writer
	)

	BeforeEach(func() {
		mintTLS = mockhandshake.NewMockMintTLS(mockCtrl)
		extHandler = mocks.NewMockTLSExtensionHandler(mockCtrl)
		conn = newMockPacketConn()
		config := &Config{
			Versions: []protocol.VersionNumber{protocol.VersionTLS},
		}
		var err error
		server, sessionChan, err = newServerTLS(conn, config, nil, testdata.GetTLSConfig())
		Expect(err).ToNot(HaveOccurred())
		server.newMintConn = func(bc *handshake.CryptoStreamConn, v protocol.VersionNumber) (handshake.MintTLS, <-chan handshake.TransportParameters, error) {
			mintReply = bc
			return mintTLS, extHandler.GetPeerParams(), nil
		}
	})

	getPacket := func(f wire.Frame) (*wire.Header, []byte) {
		hdrBuf := &bytes.Buffer{}
		hdr := &wire.Header{
			IsLongHeader: true,
			PacketNumber: 1,
			Version:      protocol.VersionTLS,
		}
		err := hdr.Write(hdrBuf, protocol.PerspectiveClient, protocol.VersionTLS)
		Expect(err).ToNot(HaveOccurred())
		hdr.Raw = hdrBuf.Bytes()
		aead, err := crypto.NewNullAEAD(protocol.PerspectiveClient, 0, protocol.VersionTLS)
		Expect(err).ToNot(HaveOccurred())
		buf := &bytes.Buffer{}
		err = f.Write(buf, protocol.VersionTLS)
		Expect(err).ToNot(HaveOccurred())
		// pad the packet such that is has exactly the required minimum size
		buf.Write(bytes.Repeat([]byte{0}, protocol.MinInitialPacketSize-len(hdr.Raw)-aead.Overhead()-buf.Len()))
		data := aead.Seal(nil, buf.Bytes(), 1, hdr.Raw)
		Expect(len(hdr.Raw) + len(data)).To(Equal(protocol.MinInitialPacketSize))
		return hdr, data
	}

	unpackPacket := func(data []byte) (*wire.Header, []byte) {
		r := bytes.NewReader(conn.dataWritten.Bytes())
		hdr, err := wire.ParseHeaderSentByServer(r, protocol.VersionTLS)
		Expect(err).ToNot(HaveOccurred())
		hdr.Raw = data[:len(data)-r.Len()]
		aead, err := crypto.NewNullAEAD(protocol.PerspectiveClient, hdr.ConnectionID, protocol.VersionTLS)
		Expect(err).ToNot(HaveOccurred())
		payload, err := aead.Open(nil, data[len(data)-r.Len():], hdr.PacketNumber, hdr.Raw)
		Expect(err).ToNot(HaveOccurred())
		return hdr, payload
	}

	It("sends a version negotiation packet if it doesn't support the version", func() {
		server.HandleInitial(nil, &wire.Header{Version: 0x1337}, bytes.Repeat([]byte{0}, protocol.MinInitialPacketSize))
		Expect(conn.dataWritten.Len()).ToNot(BeZero())
		hdr, err := wire.ParseHeaderSentByServer(bytes.NewReader(conn.dataWritten.Bytes()), protocol.VersionUnknown)
		Expect(err).ToNot(HaveOccurred())
		Expect(hdr.IsVersionNegotiation).To(BeTrue())
		Expect(sessionChan).ToNot(Receive())
	})

	It("drops too small packets", func() {
		hdr, data := getPacket(&wire.StreamFrame{Data: []byte("Client Hello")})
		data = data[:len(data)-1] // the packet is now 1 byte too small
		server.HandleInitial(nil, hdr, data)
		Expect(conn.dataWritten.Len()).To(BeZero())
	})

	It("ignores packets with invalid contents", func() {
		hdr, data := getPacket(&wire.StreamFrame{StreamID: 10, Offset: 11, Data: []byte("foobar")})
		server.HandleInitial(nil, hdr, data)
		Expect(conn.dataWritten.Len()).To(BeZero())
		Expect(sessionChan).ToNot(Receive())
	})

	It("replies with a Retry packet, if a Cookie is required", func() {
		extHandler.EXPECT().GetPeerParams()
		mintTLS.EXPECT().Handshake().Return(mint.AlertStatelessRetry).Do(func() {
			mintReply.Write([]byte("Retry with this Cookie"))
		})
		hdr, data := getPacket(&wire.StreamFrame{Data: []byte("Client Hello")})
		server.HandleInitial(nil, hdr, data)
		Expect(conn.dataWritten.Len()).ToNot(BeZero())
		hdr, err := wire.ParseHeaderSentByServer(bytes.NewReader(conn.dataWritten.Bytes()), protocol.VersionTLS)
		Expect(err).ToNot(HaveOccurred())
		Expect(hdr.Type).To(Equal(protocol.PacketTypeRetry))
		Expect(sessionChan).ToNot(Receive())
	})

	It("replies with a Handshake packet and creates a session, if no Cookie is required", func() {
		mintTLS.EXPECT().Handshake().Return(mint.AlertNoAlert).Do(func() {
			mintReply.Write([]byte("Server Hello"))
		})
		mintTLS.EXPECT().Handshake().Return(mint.AlertNoAlert)
		mintTLS.EXPECT().State().Return(mint.StateServerNegotiated)
		mintTLS.EXPECT().State().Return(mint.StateServerWaitFlight2)
		paramsChan := make(chan handshake.TransportParameters, 1)
		paramsChan <- handshake.TransportParameters{}
		extHandler.EXPECT().GetPeerParams().Return(paramsChan)
		hdr, data := getPacket(&wire.StreamFrame{Data: []byte("Client Hello")})
		done := make(chan struct{})
		go func() {
			defer GinkgoRecover()
			server.HandleInitial(nil, hdr, data)
			// the Handshake packet is written by the session
			Expect(conn.dataWritten.Len()).To(BeZero())
			close(done)
		}()
		Eventually(sessionChan).Should(Receive())
		Eventually(done).Should(BeClosed())
	})

	It("sends a CONNECTION_CLOSE, if mint returns an error", func() {
		mintTLS.EXPECT().Handshake().Return(mint.AlertAccessDenied)
		extHandler.EXPECT().GetPeerParams()
		hdr, data := getPacket(&wire.StreamFrame{Data: []byte("Client Hello")})
		server.HandleInitial(nil, hdr, data)
		// the Handshake packet is written by the session
		Expect(conn.dataWritten.Bytes()).ToNot(BeEmpty())
		// unpack the packet to check that it actually contains a CONNECTION_CLOSE
		hdr, data = unpackPacket(conn.dataWritten.Bytes())
		Expect(hdr.Type).To(Equal(protocol.PacketTypeHandshake))
		ccf, err := wire.ParseConnectionCloseFrame(bytes.NewReader(data), protocol.VersionTLS)
		Expect(err).ToNot(HaveOccurred())
		Expect(ccf.ErrorCode).To(Equal(qerr.HandshakeFailed))
		Expect(ccf.ReasonPhrase).To(Equal(mint.AlertAccessDenied.String()))
	})
})
