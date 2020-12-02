package quic

import (
	"errors"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Closed local session", func() {
	var (
		sess  packetHandler
		mconn *MockSendConn
	)

	BeforeEach(func() {
		mconn = NewMockSendConn(mockCtrl)
		sess = newClosedLocalSession(mconn, []byte("close"), protocol.PerspectiveClient, utils.DefaultLogger)
	})

	AfterEach(func() {
		Eventually(areClosedSessionsRunning).Should(BeFalse())
	})

	It("tells its perspective", func() {
		Expect(sess.getPerspective()).To(Equal(protocol.PerspectiveClient))
		// stop the session
		sess.shutdown()
	})

	It("repeats the packet containing the CONNECTION_CLOSE frame", func() {
		written := make(chan []byte)
		mconn.EXPECT().Write(gomock.Any()).Do(func(p []byte) { written <- p }).AnyTimes()
		for i := 1; i <= 20; i++ {
			sess.handlePacket(&receivedPacket{})
			if i == 1 || i == 2 || i == 4 || i == 8 || i == 16 {
				Eventually(written).Should(Receive(Equal([]byte("close")))) // receive the CONNECTION_CLOSE
			} else {
				Consistently(written, 10*time.Millisecond).Should(HaveLen(0))
			}
		}
		// stop the session
		sess.shutdown()
	})

	It("destroys sessions", func() {
		Expect(areClosedSessionsRunning()).To(BeTrue())
		sess.destroy(errors.New("destroy"))
		Eventually(areClosedSessionsRunning).Should(BeFalse())
	})
})
