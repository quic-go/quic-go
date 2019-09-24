package quic

import (
	"time"

	"github.com/lucas-clemente/quic-go/internal/utils"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("closed local session", func() {
	var (
		sess            closedSession
		mconn           *mockConnection
		receivedPackets chan *receivedPacket
	)

	BeforeEach(func() {
		mconn = newMockConnection()
		receivedPackets = make(chan *receivedPacket, 10)
		sess = newClosedLocalSession(mconn, receivedPackets, []byte("close"), utils.DefaultLogger)
	})

	It("repeats the packet containing the CONNECTION_CLOSE frame", func() {
		for i := 1; i <= 20; i++ {
			receivedPackets <- &receivedPacket{}
			if i == 1 || i == 2 || i == 4 || i == 8 || i == 16 {
				Eventually(mconn.written).Should(Receive(Equal([]byte("close")))) // receive the CONNECTION_CLOSE
			} else {
				Consistently(mconn.written, 10*time.Millisecond).Should(HaveLen(0))
			}
		}
		// stop the session
		sess.destroy()
		Eventually(areClosedSessionsRunning).Should(BeFalse())
	})

	It("destroys sessions", func() {
		Expect(areClosedSessionsRunning()).To(BeTrue())
		sess.destroy()
		Eventually(areClosedSessionsRunning).Should(BeFalse())
	})
})

var _ = Describe("closed remote session", func() {
	var (
		sess            closedSession
		receivedPackets chan *receivedPacket
	)

	BeforeEach(func() {
		receivedPackets = make(chan *receivedPacket, 10)
		sess = newClosedRemoteSession(receivedPackets)
	})

	It("discards packets", func() {
		for i := 0; i < 1000; i++ {
			receivedPackets <- &receivedPacket{}
		}
		// stop the session
		sess.destroy()
		Eventually(areClosedSessionsRunning).Should(BeFalse())
	})

	It("destroys sessions", func() {
		Expect(areClosedSessionsRunning()).To(BeTrue())
		sess.destroy()
		Eventually(areClosedSessionsRunning).Should(BeFalse())
	})
})
