package quic

import (
	"context"
	"errors"

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
			done := make(chan struct{})
			frame := &wire.DatagramFrame{Data: []byte("foobar")}
			go func() {
				defer GinkgoRecover()
				defer close(done)
				Expect(queue.AddAndWait(frame)).To(Succeed())
			}()

			Eventually(queued).Should(HaveLen(1))
			Consistently(done).ShouldNot(BeClosed())
			f := queue.Peek()
			Expect(f.Data).To(Equal([]byte("foobar")))
			Eventually(done).Should(BeClosed())
			queue.Pop()
			Expect(queue.Peek()).To(BeNil())
		})

		It("returns the same datagram multiple times, when Pop isn't called", func() {
			sent := make(chan struct{}, 1)
			go func() {
				defer GinkgoRecover()
				Expect(queue.AddAndWait(&wire.DatagramFrame{Data: []byte("foo")})).To(Succeed())
				sent <- struct{}{}
				Expect(queue.AddAndWait(&wire.DatagramFrame{Data: []byte("bar")})).To(Succeed())
				sent <- struct{}{}
			}()

			Eventually(queued).Should(HaveLen(1))
			f := queue.Peek()
			Expect(f.Data).To(Equal([]byte("foo")))
			Eventually(sent).Should(Receive())
			Expect(queue.Peek()).To(Equal(f))
			Expect(queue.Peek()).To(Equal(f))
			queue.Pop()
			Eventually(func() *wire.DatagramFrame { f = queue.Peek(); return f }).ShouldNot(BeNil())
			f = queue.Peek()
			Expect(f.Data).To(Equal([]byte("bar")))
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
