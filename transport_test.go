package quic

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"net"
	"syscall"
	"time"

	mocklogging "github.com/quic-go/quic-go/internal/mocks/logging"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/wire"
	"github.com/quic-go/quic-go/logging"

	"github.com/golang/mock/gomock"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Transport", func() {
	type packetToRead struct {
		addr net.Addr
		data []byte
		err  error
	}

	getPacketWithPacketType := func(connID protocol.ConnectionID, t protocol.PacketType, length protocol.ByteCount) []byte {
		b, err := (&wire.ExtendedHeader{
			Header: wire.Header{
				Type:             t,
				DestConnectionID: connID,
				Length:           length,
				Version:          protocol.Version1,
			},
			PacketNumberLen: protocol.PacketNumberLen2,
		}).Append(nil, protocol.Version1)
		Expect(err).ToNot(HaveOccurred())
		return b
	}

	getPacket := func(connID protocol.ConnectionID) []byte {
		return getPacketWithPacketType(connID, protocol.PacketTypeHandshake, 2)
	}

	newMockPacketConn := func(packetChan <-chan packetToRead) *MockPacketConn {
		conn := NewMockPacketConn(mockCtrl)
		conn.EXPECT().LocalAddr().Return(&net.UDPAddr{}).AnyTimes()
		conn.EXPECT().ReadFrom(gomock.Any()).DoAndReturn(func(b []byte) (int, net.Addr, error) {
			p, ok := <-packetChan
			if !ok {
				return 0, nil, errors.New("closed")
			}
			return copy(b, p.data), p.addr, p.err
		}).AnyTimes()
		// for shutdown
		conn.EXPECT().SetReadDeadline(gomock.Any()).AnyTimes()
		return conn
	}

	It("handles packets for different packet handlers on the same packet conn", func() {
		packetChan := make(chan packetToRead)
		tr := &Transport{Conn: newMockPacketConn(packetChan)}
		tr.init(true)
		phm := NewMockPacketHandlerManager(mockCtrl)
		tr.handlerMap = phm
		connID1 := protocol.ParseConnectionID([]byte{1, 2, 3, 4, 5, 6, 7, 8})
		connID2 := protocol.ParseConnectionID([]byte{8, 7, 6, 5, 4, 3, 2, 1})

		handled := make(chan struct{}, 2)
		phm.EXPECT().Get(connID1).DoAndReturn(func(protocol.ConnectionID) (packetHandler, bool) {
			h := NewMockPacketHandler(mockCtrl)
			h.EXPECT().handlePacket(gomock.Any()).Do(func(p receivedPacket) {
				defer GinkgoRecover()
				connID, err := wire.ParseConnectionID(p.data, 0)
				Expect(err).ToNot(HaveOccurred())
				Expect(connID).To(Equal(connID1))
				handled <- struct{}{}
			})
			return h, true
		})
		phm.EXPECT().Get(connID2).DoAndReturn(func(protocol.ConnectionID) (packetHandler, bool) {
			h := NewMockPacketHandler(mockCtrl)
			h.EXPECT().handlePacket(gomock.Any()).Do(func(p receivedPacket) {
				defer GinkgoRecover()
				connID, err := wire.ParseConnectionID(p.data, 0)
				Expect(err).ToNot(HaveOccurred())
				Expect(connID).To(Equal(connID2))
				handled <- struct{}{}
			})
			return h, true
		})

		packetChan <- packetToRead{data: getPacket(connID1)}
		packetChan <- packetToRead{data: getPacket(connID2)}

		Eventually(handled).Should(Receive())
		Eventually(handled).Should(Receive())

		// shutdown
		phm.EXPECT().Close(gomock.Any())
		close(packetChan)
		tr.Close()
	})

	It("closes listeners", func() {
		packetChan := make(chan packetToRead)
		tr := &Transport{Conn: newMockPacketConn(packetChan)}
		defer tr.Close()
		ln, err := tr.Listen(&tls.Config{}, nil)
		Expect(err).ToNot(HaveOccurred())
		phm := NewMockPacketHandlerManager(mockCtrl)
		tr.handlerMap = phm

		phm.EXPECT().CloseServer()
		Expect(ln.Close()).To(Succeed())

		// shutdown
		phm.EXPECT().Close(gomock.Any())
		close(packetChan)
		tr.Close()
	})

	It("drops unparseable packets", func() {
		addr := &net.UDPAddr{IP: net.IPv4(9, 8, 7, 6), Port: 1234}
		packetChan := make(chan packetToRead)
		tracer := mocklogging.NewMockTracer(mockCtrl)
		tr := &Transport{
			Conn:               newMockPacketConn(packetChan),
			ConnectionIDLength: 10,
			Tracer:             tracer,
		}
		tr.init(true)
		dropped := make(chan struct{})
		tracer.EXPECT().DroppedPacket(addr, logging.PacketTypeNotDetermined, protocol.ByteCount(4), logging.PacketDropHeaderParseError).Do(func(net.Addr, logging.PacketType, protocol.ByteCount, logging.PacketDropReason) { close(dropped) })
		packetChan <- packetToRead{
			addr: addr,
			data: []byte{0, 1, 2, 3},
		}
		Eventually(dropped).Should(BeClosed())

		// shutdown
		close(packetChan)
		tr.Close()
	})

	It("closes when reading from the conn fails", func() {
		packetChan := make(chan packetToRead)
		tr := Transport{Conn: newMockPacketConn(packetChan)}
		defer tr.Close()
		phm := NewMockPacketHandlerManager(mockCtrl)
		tr.init(true)
		tr.handlerMap = phm

		done := make(chan struct{})
		phm.EXPECT().Close(gomock.Any()).Do(func(error) { close(done) })
		packetChan <- packetToRead{err: errors.New("read failed")}
		Eventually(done).Should(BeClosed())

		// shutdown
		close(packetChan)
		tr.Close()
	})

	It("continues listening after temporary errors", func() {
		packetChan := make(chan packetToRead)
		tr := Transport{Conn: newMockPacketConn(packetChan)}
		defer tr.Close()
		phm := NewMockPacketHandlerManager(mockCtrl)
		tr.init(true)
		tr.handlerMap = phm

		tempErr := deadlineError{}
		Expect(tempErr.Temporary()).To(BeTrue())
		packetChan <- packetToRead{err: tempErr}
		// don't expect any calls to phm.Close
		time.Sleep(50 * time.Millisecond)

		// shutdown
		phm.EXPECT().Close(gomock.Any())
		close(packetChan)
		tr.Close()
	})

	It("handles short header packets resets", func() {
		connID := protocol.ParseConnectionID([]byte{2, 3, 4, 5})
		packetChan := make(chan packetToRead)
		tr := Transport{
			Conn:               newMockPacketConn(packetChan),
			ConnectionIDLength: connID.Len(),
		}
		tr.init(true)
		defer tr.Close()
		phm := NewMockPacketHandlerManager(mockCtrl)
		tr.handlerMap = phm

		var token protocol.StatelessResetToken
		rand.Read(token[:])

		var b []byte
		b, err := wire.AppendShortHeader(b, connID, 1337, 2, protocol.KeyPhaseOne)
		Expect(err).ToNot(HaveOccurred())
		b = append(b, token[:]...)
		conn := NewMockPacketHandler(mockCtrl)
		gomock.InOrder(
			phm.EXPECT().GetByResetToken(token),
			phm.EXPECT().Get(connID).Return(conn, true),
			conn.EXPECT().handlePacket(gomock.Any()).Do(func(p receivedPacket) {
				Expect(p.data).To(Equal(b))
				Expect(p.rcvTime).To(BeTemporally("~", time.Now(), time.Second))
			}),
		)
		packetChan <- packetToRead{data: b}

		// shutdown
		phm.EXPECT().Close(gomock.Any())
		close(packetChan)
		tr.Close()
	})

	It("handles stateless resets", func() {
		connID := protocol.ParseConnectionID([]byte{2, 3, 4, 5})
		packetChan := make(chan packetToRead)
		tr := Transport{Conn: newMockPacketConn(packetChan)}
		tr.init(true)
		defer tr.Close()
		phm := NewMockPacketHandlerManager(mockCtrl)
		tr.handlerMap = phm

		var token protocol.StatelessResetToken
		rand.Read(token[:])

		var b []byte
		b, err := wire.AppendShortHeader(b, connID, 1337, 2, protocol.KeyPhaseOne)
		Expect(err).ToNot(HaveOccurred())
		b = append(b, token[:]...)
		conn := NewMockPacketHandler(mockCtrl)
		destroyed := make(chan struct{})
		gomock.InOrder(
			phm.EXPECT().GetByResetToken(token).Return(conn, true),
			conn.EXPECT().destroy(gomock.Any()).Do(func(err error) {
				Expect(err).To(MatchError(&StatelessResetError{Token: token}))
				close(destroyed)
			}),
		)
		packetChan <- packetToRead{data: b}
		Eventually(destroyed).Should(BeClosed())

		// shutdown
		phm.EXPECT().Close(gomock.Any())
		close(packetChan)
		tr.Close()
	})

	It("sends stateless resets", func() {
		connID := protocol.ParseConnectionID([]byte{2, 3, 4, 5})
		packetChan := make(chan packetToRead)
		conn := newMockPacketConn(packetChan)
		tr := Transport{
			Conn:               conn,
			StatelessResetKey:  &StatelessResetKey{1, 2, 3, 4},
			ConnectionIDLength: connID.Len(),
		}
		tr.init(true)
		defer tr.Close()
		phm := NewMockPacketHandlerManager(mockCtrl)
		tr.handlerMap = phm

		var b []byte
		b, err := wire.AppendShortHeader(b, connID, 1337, 2, protocol.KeyPhaseOne)
		Expect(err).ToNot(HaveOccurred())
		b = append(b, make([]byte, protocol.MinStatelessResetSize-len(b)+1)...)

		var token protocol.StatelessResetToken
		rand.Read(token[:])
		written := make(chan struct{})
		gomock.InOrder(
			phm.EXPECT().GetByResetToken(gomock.Any()),
			phm.EXPECT().Get(connID),
			phm.EXPECT().GetStatelessResetToken(connID).Return(token),
			conn.EXPECT().WriteTo(gomock.Any(), gomock.Any()).Do(func(b []byte, _ net.Addr) {
				defer close(written)
				Expect(bytes.Contains(b, token[:])).To(BeTrue())
			}),
		)
		packetChan <- packetToRead{data: b}
		Eventually(written).Should(BeClosed())

		// shutdown
		phm.EXPECT().Close(gomock.Any())
		close(packetChan)
		tr.Close()
	})

	It("closes uninitialized Transport and closes underlying PacketConn", func() {
		packetChan := make(chan packetToRead)
		pconn := newMockPacketConn(packetChan)

		tr := &Transport{
			Conn:        pconn,
			createdConn: true, // owns pconn
		}
		// NO init

		// shutdown
		close(packetChan)
		pconn.EXPECT().Close()
		Expect(tr.Close()).To(Succeed())
	})

	It("doesn't add the PacketConn to the multiplexer if (*Transport).init fails", func() {
		packetChan := make(chan packetToRead)
		pconn := newMockPacketConn(packetChan)
		syscallconn := &mockSyscallConn{pconn}

		tr := &Transport{
			Conn: syscallconn,
		}

		err := tr.init(false)
		Expect(err).To(HaveOccurred())
		conns := getMultiplexer().(*connMultiplexer).conns
		Expect(len(conns)).To(BeZero())
	})
})

type mockSyscallConn struct {
	net.PacketConn
}

func (c *mockSyscallConn) SyscallConn() (syscall.RawConn, error) {
	return nil, errors.New("mocked")
}
