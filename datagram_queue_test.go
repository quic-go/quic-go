package quic

import (
	"errors"

	"github.com/lucas-clemente/quic-go/internal/wire"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Datagram Queue", func() {
	var queue *datagramQueue
	var queued chan struct{}

	BeforeEach(func() {
		queued = make(chan struct{}, 100)
		queue = newDatagramQueue(func() {
			queued <- struct{}{}
		})
	})

	It("returns nil when there's no datagram to send", func() {
		Expect(queue.Get()).To(BeNil())
	})

	It("queues a datagram", func() {
		done := make(chan struct{})
		go func() {
			defer GinkgoRecover()
			defer close(done)
			Expect(queue.AddAndWait(&wire.DatagramFrame{Data: []byte("foobar")})).To(Succeed())
		}()

		Eventually(queued).Should(HaveLen(1))
		Consistently(done).ShouldNot(BeClosed())
		f := queue.Get()
		Expect(f).ToNot(BeNil())
		Expect(f.Data).To(Equal([]byte("foobar")))
		Eventually(done).Should(BeClosed())
		Expect(queue.Get()).To(BeNil())
	})

	It("closes", func() {
		errChan := make(chan error, 1)
		go func() {
			defer GinkgoRecover()
			errChan <- queue.AddAndWait(&wire.DatagramFrame{Data: []byte("foobar")})
		}()

		Consistently(errChan).ShouldNot(Receive())
		queue.CloseWithError(errors.New("test error"))
		Eventually(errChan).Should(Receive(MatchError("test error")))
	})
})
