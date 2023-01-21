package quic

import (
	"net"

	mocklogging "github.com/quic-go/quic-go/internal/mocks/logging"

	"github.com/golang/mock/gomock"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

type testConn struct {
	counter int
	net.PacketConn
}

var _ = Describe("Multiplexer", func() {
	It("adds a new packet conn ", func() {
		conn := NewMockPacketConn(mockCtrl)
		conn.EXPECT().ReadFrom(gomock.Any()).Do(func([]byte) { <-(make(chan struct{})) }).MaxTimes(1)
		conn.EXPECT().LocalAddr().Return(&net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 1234})
		_, err := getMultiplexer().AddConn(conn, 8, nil, nil)
		Expect(err).ToNot(HaveOccurred())
	})

	It("recognizes when the same connection is added twice", func() {
		srk := &StatelessResetKey{'f', 'o', 'o', 'b', 'a', 'r'}
		pconn := NewMockPacketConn(mockCtrl)
		pconn.EXPECT().LocalAddr().Return(&net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 4321}).Times(2)
		pconn.EXPECT().ReadFrom(gomock.Any()).Do(func([]byte) { <-(make(chan struct{})) }).MaxTimes(1)
		conn := testConn{PacketConn: pconn}
		tracer := mocklogging.NewMockTracer(mockCtrl)
		_, err := getMultiplexer().AddConn(conn, 8, srk, tracer)
		Expect(err).ToNot(HaveOccurred())
		conn.counter++
		_, err = getMultiplexer().AddConn(conn, 8, srk, tracer)
		Expect(err).ToNot(HaveOccurred())
		Expect(getMultiplexer().(*connMultiplexer).conns).To(HaveLen(1))
	})

	It("errors when adding an existing conn with a different connection ID length", func() {
		conn := NewMockPacketConn(mockCtrl)
		conn.EXPECT().ReadFrom(gomock.Any()).Do(func([]byte) { <-(make(chan struct{})) }).MaxTimes(1)
		conn.EXPECT().LocalAddr().Return(&net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 1234}).Times(2)
		_, err := getMultiplexer().AddConn(conn, 5, nil, nil)
		Expect(err).ToNot(HaveOccurred())
		_, err = getMultiplexer().AddConn(conn, 6, nil, nil)
		Expect(err).To(MatchError("cannot use 6 byte connection IDs on a connection that is already using 5 byte connction IDs"))
	})

	It("errors when adding an existing conn with a different stateless rest key", func() {
		srk1 := &StatelessResetKey{'f', 'o', 'o'}
		srk2 := &StatelessResetKey{'b', 'a', 'r'}
		conn := NewMockPacketConn(mockCtrl)
		conn.EXPECT().ReadFrom(gomock.Any()).Do(func([]byte) { <-(make(chan struct{})) }).MaxTimes(1)
		conn.EXPECT().LocalAddr().Return(&net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 1234}).Times(2)
		_, err := getMultiplexer().AddConn(conn, 7, srk1, nil)
		Expect(err).ToNot(HaveOccurred())
		_, err = getMultiplexer().AddConn(conn, 7, srk2, nil)
		Expect(err).To(MatchError("cannot use different stateless reset keys on the same packet conn"))
	})

	It("errors when adding an existing conn with different tracers", func() {
		conn := NewMockPacketConn(mockCtrl)
		conn.EXPECT().ReadFrom(gomock.Any()).Do(func([]byte) { <-(make(chan struct{})) }).MaxTimes(1)
		conn.EXPECT().LocalAddr().Return(&net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 1234}).Times(2)
		_, err := getMultiplexer().AddConn(conn, 7, nil, mocklogging.NewMockTracer(mockCtrl))
		Expect(err).ToNot(HaveOccurred())
		_, err = getMultiplexer().AddConn(conn, 7, nil, mocklogging.NewMockTracer(mockCtrl))
		Expect(err).To(MatchError("cannot use different tracers on the same packet conn"))
	})
})
