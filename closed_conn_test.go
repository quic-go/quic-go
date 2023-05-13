package quic

import (
	"net"

	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/utils"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Closed local connection", func() {
	It("tells its perspective", func() {
		conn := newClosedLocalConn(nil, protocol.PerspectiveClient, utils.DefaultLogger)
		Expect(conn.getPerspective()).To(Equal(protocol.PerspectiveClient))
		// stop the connection
		conn.shutdown()
	})

	It("repeats the packet containing the CONNECTION_CLOSE frame", func() {
		written := make(chan net.Addr, 1)
		conn := newClosedLocalConn(
			func(addr net.Addr, _ packetInfo) { written <- addr },
			protocol.PerspectiveClient,
			utils.DefaultLogger,
		)
		addr := &net.UDPAddr{IP: net.IPv4(127, 1, 2, 3), Port: 1337}
		for i := 1; i <= 20; i++ {
			conn.handlePacket(receivedPacket{remoteAddr: addr})
			if i == 1 || i == 2 || i == 4 || i == 8 || i == 16 {
				Expect(written).To(Receive(Equal(addr))) // receive the CONNECTION_CLOSE
			} else {
				Expect(written).ToNot(Receive())
			}
		}
	})
})
