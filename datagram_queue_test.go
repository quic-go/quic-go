package quic

import (
	"context"
	"errors"
	"time"

	"github.com/quic-go/quic-go/internal/utils"
	"github.com/quic-go/quic-go/internal/wire"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Datagram Queue", func() {
	var queue *datagramQueue
	var queued chan struct{}

	BeforeEach(func() {
		queued = make(chan struct{}, 100)
		queue = newDatagramQueue(func() { queued <- struct{}{} }, utils.DefaultLogger)
	})

	Context("sending", func() {
		It("returns nil when there's no datagram to send", func() {
			Expect(queue.Peek()).To(BeNil())
		})

		It("queues a datagram", func() {
			frame := &wire.DatagramFrame{Data: []byte("foobar")}
			Expect(queue.Add(frame)).To(Succeed())
			Expect(queued).To(HaveLen(1))
			f := queue.Peek()
			Expect(f.Data).To(Equal([]byte("foobar")))
			queue.Pop()
			Expect(queue.Peek()).To(BeNil())
		})

		It("blocks when the maximum number of datagrams have been queued", func() {
			for i := 0; i < maxDatagramSendQueueLen; i++ {
				Expect(queue.Add(&wire.DatagramFrame{Data: []byte{0}})).To(Succeed())
			}
			errChan := make(chan error, 1)
			go func() {
				defer GinkgoRecover()
				errChan <- queue.Add(&wire.DatagramFrame{Data: []byte("foobar")})
			}()
			Consistently(errChan, 50*time.Millisecond).ShouldNot(Receive())
			Expect(queue.Peek()).ToNot(BeNil())
			Consistently(errChan, 50*time.Millisecond).ShouldNot(Receive())
			queue.Pop()
			Eventually(errChan).Should(Receive(BeNil()))
			for i := 1; i < maxDatagramSendQueueLen; i++ {
				queue.Pop()
			}
			f := queue.Peek()
			Expect(f).ToNot(BeNil())
			Expect(f.Data).To(Equal([]byte("foobar")))
		})

		It("returns the same datagram multiple times, when Pop isn't called", func() {
			Expect(queue.Add(&wire.DatagramFrame{Data: []byte("foo")})).To(Succeed())
			Expect(queue.Add(&wire.DatagramFrame{Data: []byte("bar")})).To(Succeed())

			Eventually(queued).Should(HaveLen(2))
			f := queue.Peek()
			Expect(f.Data).To(Equal([]byte("foo")))
			Expect(queue.Peek()).To(Equal(f))
			Expect(queue.Peek()).To(Equal(f))
			queue.Pop()
			f = queue.Peek()
			Expect(f).ToNot(BeNil())
			Expect(f.Data).To(Equal([]byte("bar")))
		})

		It("closes", func() {
			for i := 0; i < maxDatagramSendQueueLen; i++ {
				Expect(queue.Add(&wire.DatagramFrame{Data: []byte("foo")})).To(Succeed())
			}
			errChan := make(chan error, 1)
			go func() {
				defer GinkgoRecover()
				errChan <- queue.Add(&wire.DatagramFrame{Data: []byte("foo")})
			}()
			Consistently(errChan, 25*time.Millisecond).ShouldNot(Receive())
			testErr := errors.New("test error")
			queue.CloseWithError(testErr)
			Eventually(errChan).Should(Receive(MatchError(testErr)))
		})
	})

	Context("receiving", func() {
		It("receives DATAGRAM frames", func() {
			queue.HandleDatagramFrame(&wire.DatagramFrame{Data: []byte("foo")})
			queue.HandleDatagramFrame(&wire.DatagramFrame{Data: []byte("bar")})
			data, err := queue.Receive(context.Background())
			Expect(err).ToNot(HaveOccurred())
			Expect(data).To(Equal([]byte("foo")))
			data, err = queue.Receive(context.Background())
			Expect(err).ToNot(HaveOccurred())
			Expect(data).To(Equal([]byte("bar")))
		})

		It("blocks until a frame is received", func() {
			c := make(chan []byte, 1)
			go func() {
				defer GinkgoRecover()
				data, err := queue.Receive(context.Background())
				Expect(err).ToNot(HaveOccurred())
				c <- data
			}()

			Consistently(c).ShouldNot(Receive())
			queue.HandleDatagramFrame(&wire.DatagramFrame{Data: []byte("foobar")})
			Eventually(c).Should(Receive(Equal([]byte("foobar"))))
		})

		It("blocks until context is done", func() {
			ctx, cancel := context.WithCancel(context.Background())
			errChan := make(chan error)
			go func() {
				defer GinkgoRecover()
				_, err := queue.Receive(ctx)
				errChan <- err
			}()

			Consistently(errChan).ShouldNot(Receive())
			cancel()
			Eventually(errChan).Should(Receive(Equal(context.Canceled)))
		})

		It("closes", func() {
			errChan := make(chan error, 1)
			go func() {
				defer GinkgoRecover()
				_, err := queue.Receive(context.Background())
				errChan <- err
			}()

			Consistently(errChan).ShouldNot(Receive())
			queue.CloseWithError(errors.New("test error"))
			Eventually(errChan).Should(Receive(MatchError("test error")))
		})
	})
})
