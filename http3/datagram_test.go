package http3

import (
	"context"
	"errors"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Datagrams", func() {
	It("receives a datagram", func() {
		dg := newDatagrammer(nil)
		dg.enqueue([]byte("foobar"))
		data, err := dg.Receive(context.Background())
		Expect(err).ToNot(HaveOccurred())
		Expect(data).To(Equal([]byte("foobar")))
	})

	It("queues up to 32 datagrams", func() {
		dg := newDatagrammer(nil)
		for i := 0; i < streamDatagramQueueLen+1; i++ {
			dg.enqueue([]byte{uint8(i)})
		}
		for i := 0; i < streamDatagramQueueLen; i++ {
			data, err := dg.Receive(context.Background())
			Expect(err).ToNot(HaveOccurred())
			Expect(data[0]).To(BeEquivalentTo(i))
		}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_, err := dg.Receive(ctx)
		Expect(err).To(MatchError(context.Canceled))
	})

	It("blocks until a new datagram is received", func() {
		dg := newDatagrammer(nil)
		done := make(chan struct{})
		go func() {
			defer GinkgoRecover()
			defer close(done)
			data, err := dg.Receive(context.Background())
			Expect(err).ToNot(HaveOccurred())
			Expect(data).To(Equal([]byte("foobar")))
		}()

		Consistently(done, 50*time.Millisecond).ShouldNot(BeClosed())
		dg.enqueue([]byte("foobar"))
		Eventually(done).Should(BeClosed())
	})

	It("drops datagrams when the stream's receive side is closed", func() {
		dg := newDatagrammer(nil)
		dg.enqueue([]byte("foo"))
		testErr := errors.New("test error")
		dg.SetReceiveError(testErr)
		dg.enqueue([]byte("bar"))
		data, err := dg.Receive(context.Background())
		Expect(err).ToNot(HaveOccurred())
		Expect(data).To(Equal([]byte("foo")))
		_, err = dg.Receive(context.Background())
		Expect(err).To(MatchError(testErr))
	})

	It("sends datagrams", func() {
		var sent []byte
		testErr := errors.New("test error")
		dg := newDatagrammer(func(b []byte) error {
			sent = b
			return testErr
		})
		Expect(dg.Send([]byte("foobar"))).To(MatchError(testErr))
		Expect(sent).To(Equal([]byte("foobar")))
	})
})
