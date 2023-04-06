package self_test

import (
	"context"
	"fmt"
	"io"
	"net"
	"sync"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/internal/protocol"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Unidirectional Streams", func() {
	const numStreams = 500

	var (
		server     *quic.Listener
		serverAddr string
	)

	BeforeEach(func() {
		var err error
		server, err = quic.ListenAddr("localhost:0", getTLSConfig(), getQuicConfig(nil))
		Expect(err).ToNot(HaveOccurred())
		serverAddr = fmt.Sprintf("localhost:%d", server.Addr().(*net.UDPAddr).Port)
	})

	AfterEach(func() {
		server.Close()
	})

	dataForStream := func(id protocol.StreamID) []byte {
		return GeneratePRData(10 * int(id))
	}

	runSendingPeer := func(conn quic.Connection) {
		for i := 0; i < numStreams; i++ {
			str, err := conn.OpenUniStreamSync(context.Background())
			Expect(err).ToNot(HaveOccurred())
			go func() {
				defer GinkgoRecover()
				_, err := str.Write(dataForStream(str.StreamID()))
				Expect(err).ToNot(HaveOccurred())
				Expect(str.Close()).To(Succeed())
			}()
		}
	}

	runReceivingPeer := func(conn quic.Connection) {
		var wg sync.WaitGroup
		wg.Add(numStreams)
		for i := 0; i < numStreams; i++ {
			str, err := conn.AcceptUniStream(context.Background())
			Expect(err).ToNot(HaveOccurred())
			go func() {
				defer GinkgoRecover()
				defer wg.Done()
				data, err := io.ReadAll(str)
				Expect(err).ToNot(HaveOccurred())
				Expect(data).To(Equal(dataForStream(str.StreamID())))
			}()
		}
		wg.Wait()
	}

	It(fmt.Sprintf("client opening %d streams to a server", numStreams), func() {
		go func() {
			defer GinkgoRecover()
			conn, err := server.Accept(context.Background())
			Expect(err).ToNot(HaveOccurred())
			runReceivingPeer(conn)
			conn.CloseWithError(0, "")
		}()

		client, err := quic.DialAddr(
			context.Background(),
			serverAddr,
			getTLSClientConfig(),
			getQuicConfig(nil),
		)
		Expect(err).ToNot(HaveOccurred())
		runSendingPeer(client)
		<-client.Context().Done()
	})

	It(fmt.Sprintf("server opening %d streams to a client", numStreams), func() {
		done := make(chan struct{})
		go func() {
			defer GinkgoRecover()
			defer close(done)
			conn, err := server.Accept(context.Background())
			Expect(err).ToNot(HaveOccurred())
			runSendingPeer(conn)
			<-conn.Context().Done()
		}()

		client, err := quic.DialAddr(
			context.Background(),
			serverAddr,
			getTLSClientConfig(),
			getQuicConfig(nil),
		)
		Expect(err).ToNot(HaveOccurred())
		runReceivingPeer(client)
		client.CloseWithError(0, "")
	})

	It(fmt.Sprintf("client and server opening %d streams each and sending data to the peer", numStreams), func() {
		done1 := make(chan struct{})
		go func() {
			defer GinkgoRecover()
			conn, err := server.Accept(context.Background())
			Expect(err).ToNot(HaveOccurred())
			done := make(chan struct{})
			go func() {
				defer GinkgoRecover()
				runReceivingPeer(conn)
				close(done)
			}()
			runSendingPeer(conn)
			<-done
			close(done1)
		}()

		client, err := quic.DialAddr(
			context.Background(),
			serverAddr,
			getTLSClientConfig(),
			getQuicConfig(nil),
		)
		Expect(err).ToNot(HaveOccurred())
		done2 := make(chan struct{})
		go func() {
			defer GinkgoRecover()
			runSendingPeer(client)
			close(done2)
		}()
		runReceivingPeer(client)
		<-done1
		<-done2
	})
})
