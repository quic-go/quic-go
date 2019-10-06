package quic

import (
	"errors"

	"github.com/lucas-clemente/quic-go/internal/utils"
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
		}, utils.DefaultLogger)
	})

	Context("sending", func() {
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

	Context("receiving", func() {
		It("receives DATAGRAM frames", func() {
			queue.HandleDatagramFrame(&wire.DatagramFrame{Data: []byte("foo")})
			queue.HandleDatagramFrame(&wire.DatagramFrame{Data: []byte("bar")})
			data, err := queue.Receive()
			Expect(err).ToNot(HaveOccurred())
			Expect(data).To(Equal([]byte("foo")))
			data, err = queue.Receive()
			Expect(err).ToNot(HaveOccurred())
			Expect(data).To(Equal([]byte("bar")))
		})

		It("blocks until a frame is received", func() {
			c := make(chan []byte, 1)
			go func() {
				defer GinkgoRecover()
				data, err := queue.Receive()
				Expect(err).ToNot(HaveOccurred())
				c <- data
			}()

			Consistently(c).ShouldNot(Receive())
			queue.HandleDatagramFrame(&wire.DatagramFrame{Data: []byte("foobar")})
			Eventually(c).Should(Receive(Equal([]byte("foobar"))))
		})

		It("closes", func() {
			errChan := make(chan error, 1)
			go func() {
				defer GinkgoRecover()
				_, err := queue.Receive()
				errChan <- err
			}()

			Consistently(errChan).ShouldNot(Receive())
			queue.CloseWithError(errors.New("test error"))
			Eventually(errChan).Should(Receive(MatchError("test error")))
		})
	})
})
