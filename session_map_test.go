package quic

import (
	"time"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Session Handler", func() {
	var handler *sessionMap

	BeforeEach(func() {
		handler = newSessionMap().(*sessionMap)
	})

	It("adds and gets", func() {
		connID := protocol.ConnectionID{1, 2, 3, 4, 5}
		sess := &mockSession{}
		handler.Add(connID, sess)
		session, ok := handler.Get(connID)
		Expect(ok).To(BeTrue())
		Expect(session).To(Equal(sess))
	})

	It("deletes", func() {
		connID := protocol.ConnectionID{1, 2, 3, 4, 5}
		handler.Add(connID, &mockSession{})
		handler.Remove(connID)
		session, ok := handler.Get(connID)
		Expect(ok).To(BeTrue())
		Expect(session).To(BeNil())
	})

	It("deletes nil session entries after a wait time", func() {
		handler.deleteClosedSessionsAfter = 25 * time.Millisecond
		connID := protocol.ConnectionID{1, 2, 3, 4, 5}
		handler.Add(connID, &mockSession{})
		handler.Remove(connID)
		Eventually(func() bool {
			_, ok := handler.Get(connID)
			return ok
		}).Should(BeFalse())
	})

	It("closes", func() {
		sess1 := NewMockPacketHandler(mockCtrl)
		sess1.EXPECT().Close(nil)
		sess2 := NewMockPacketHandler(mockCtrl)
		sess2.EXPECT().Close(nil)
		handler.Add(protocol.ConnectionID{1, 1, 1, 1}, sess1)
		handler.Add(protocol.ConnectionID{2, 2, 2, 2}, sess2)
		handler.Close()
	})
})
