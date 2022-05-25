package quic

import (
	"errors"
	"net"

	"github.com/golang/mock/gomock"
	mocklogging "github.com/lucas-clemente/quic-go/internal/mocks/logging"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

type testConn struct {
	counter int
	net.PacketConn
}

var _ = Describe("Multiplexer", func() {
	var (
		conn        *MockPacketConn
		testRunning chan struct{}
	)
	localAddr := &net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 1234}

	BeforeEach(func() {
		testRunning = make(chan struct{})
		conn = NewMockPacketConn(mockCtrl)
		conn.EXPECT().ReadFrom(gomock.Any()).DoAndReturn(func([]byte) (int, net.Addr, error) {
			<-testRunning
			return 0, nil, errors.New("test done")
		}).MaxTimes(1)
	})

	AfterEach(func() {
		conn.EXPECT().LocalAddr().Return(localAddr)
		close(testRunning)
	})

	It("adds a new packet conn ", func() {
		done := make(chan struct{})
		conn.EXPECT().LocalAddr().Return(localAddr).Do(func() { close(done) })
		_, err := getMultiplexer().AddConn(conn, 8, nil, nil)
		Expect(err).ToNot(HaveOccurred())
		Eventually(done).Should(BeClosed())
	})

	It("recognizes when the same connection is added twice", func() {
		conn.EXPECT().LocalAddr().Return(localAddr).Times(2)
		tconn := testConn{PacketConn: conn}
		tracer := mocklogging.NewMockTracer(mockCtrl)
		_, err := getMultiplexer().AddConn(tconn, 8, []byte("foobar"), tracer)
		Expect(err).ToNot(HaveOccurred())
		tconn.counter++
		_, err = getMultiplexer().AddConn(tconn, 8, []byte("foobar"), tracer)
		Expect(err).ToNot(HaveOccurred())
		Expect(getMultiplexer().(*connMultiplexer).conns).To(HaveLen(1))
	})

	It("errors when adding an existing conn with a different connection ID length", func() {
		conn.EXPECT().LocalAddr().Return(localAddr).Times(2)
		_, err := getMultiplexer().AddConn(conn, 5, nil, nil)
		Expect(err).ToNot(HaveOccurred())
		_, err = getMultiplexer().AddConn(conn, 6, nil, nil)
		Expect(err).To(MatchError("cannot use 6 byte connection IDs on a connection that is already using 5 byte connction IDs"))
	})

	It("errors when adding an existing conn with a different stateless rest key", func() {
		conn.EXPECT().LocalAddr().Return(localAddr).Times(2)
		_, err := getMultiplexer().AddConn(conn, 7, []byte("foobar"), nil)
		Expect(err).ToNot(HaveOccurred())
		_, err = getMultiplexer().AddConn(conn, 7, []byte("raboof"), nil)
		Expect(err).To(MatchError("cannot use different stateless reset keys on the same packet conn"))
	})

	It("errors when adding an existing conn with different tracers", func() {
		conn.EXPECT().LocalAddr().Return(localAddr).Times(2)
		_, err := getMultiplexer().AddConn(conn, 7, nil, mocklogging.NewMockTracer(mockCtrl))
		Expect(err).ToNot(HaveOccurred())
		_, err = getMultiplexer().AddConn(conn, 7, nil, mocklogging.NewMockTracer(mockCtrl))
		Expect(err).To(MatchError("cannot use different tracers on the same packet conn"))
	})
})
