package quic

import (
	"errors"
	"time"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Closed local session", func() {
	var (
		sess  packetHandler
		mconn *mockConnection
	)

	BeforeEach(func() {
		mconn = newMockConnection()
		sess = newClosedLocalSession(mconn, []byte("close"), protocol.PerspectiveClient, utils.DefaultLogger)
	})

	AfterEach(func() {
		Eventually(areClosedSessionsRunning).Should(BeFalse())
	})

	It("tells its perspective", func() {
		Expect(sess.getPerspective()).To(Equal(protocol.PerspectiveClient))
		// stop the session
		Expect(sess.Close()).To(Succeed())
	})

	It("repeats the packet containing the CONNECTION_CLOSE frame", func() {
		for i := 1; i <= 20; i++ {
			sess.handlePacket(&receivedPacket{})
			if i == 1 || i == 2 || i == 4 || i == 8 || i == 16 {
				Eventually(mconn.written).Should(Receive(Equal([]byte("close")))) // receive the CONNECTION_CLOSE
			} else {
				Consistently(mconn.written, 10*time.Millisecond).Should(HaveLen(0))
			}
		}
		// stop the session
		Expect(sess.Close()).To(Succeed())
	})

	It("destroys sessions", func() {
		Expect(areClosedSessionsRunning()).To(BeTrue())
		sess.destroy(errors.New("destroy"))
		Eventually(areClosedSessionsRunning).Should(BeFalse())
	})
})
