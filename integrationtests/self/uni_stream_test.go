package self_test

import (
	"context"
	"fmt"
	"io/ioutil"
	"net"
	"sync"

	quic "github.com/lucas-clemente/quic-go"
	"github.com/lucas-clemente/quic-go/internal/protocol"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Unidirectional Streams", func() {
	const numStreams = 500

	var (
		server     quic.Listener
		serverAddr string
		qconf      *quic.Config
	)

	BeforeEach(func() {
		var err error
		qconf = &quic.Config{Versions: []protocol.VersionNumber{protocol.VersionTLS}}
		server, err = quic.ListenAddr("localhost:0", getTLSConfig(), qconf)
		Expect(err).ToNot(HaveOccurred())
		serverAddr = fmt.Sprintf("localhost:%d", server.Addr().(*net.UDPAddr).Port)
	})

	AfterEach(func() {
		server.Close()
	})

	dataForStream := func(id protocol.StreamID) []byte {
		return GeneratePRData(10 * int(id))
	}

	runSendingPeer := func(sess quic.Session) {
		for i := 0; i < numStreams; i++ {
			str, err := sess.OpenUniStreamSync(context.Background())
			Expect(err).ToNot(HaveOccurred())
			go func() {
				defer GinkgoRecover()
				_, err := str.Write(dataForStream(str.StreamID()))
				Expect(err).ToNot(HaveOccurred())
				Expect(str.Close()).To(Succeed())
			}()
		}
	}

	runReceivingPeer := func(sess quic.Session) {
		var wg sync.WaitGroup
		wg.Add(numStreams)
		for i := 0; i < numStreams; i++ {
			str, err := sess.AcceptUniStream(context.Background())
			Expect(err).ToNot(HaveOccurred())
			go func() {
				defer GinkgoRecover()
				defer wg.Done()
				data, err := ioutil.ReadAll(str)
				Expect(err).ToNot(HaveOccurred())
				Expect(data).To(Equal(dataForStream(str.StreamID())))
			}()
		}
		wg.Wait()
	}

	It(fmt.Sprintf("client opening %d streams to a server", numStreams), func() {
		go func() {
			defer GinkgoRecover()
			sess, err := server.Accept(context.Background())
			Expect(err).ToNot(HaveOccurred())
			runReceivingPeer(sess)
			sess.Close()
		}()

		client, err := quic.DialAddr(
			serverAddr,
			getTLSClientConfig(),
			qconf,
		)
		Expect(err).ToNot(HaveOccurred())
		runSendingPeer(client)
		<-client.Context().Done()
	})

	It(fmt.Sprintf("server opening %d streams to a client", numStreams), func() {
		go func() {
			defer GinkgoRecover()
			sess, err := server.Accept(context.Background())
			Expect(err).ToNot(HaveOccurred())
			runSendingPeer(sess)
		}()

		client, err := quic.DialAddr(
			serverAddr,
			getTLSClientConfig(),
			qconf,
		)
		Expect(err).ToNot(HaveOccurred())
		runReceivingPeer(client)
	})

	It(fmt.Sprintf("client and server opening %d streams each and sending data to the peer", numStreams), func() {
		done1 := make(chan struct{})
		go func() {
			defer GinkgoRecover()
			sess, err := server.Accept(context.Background())
			Expect(err).ToNot(HaveOccurred())
			done := make(chan struct{})
			go func() {
				defer GinkgoRecover()
				runReceivingPeer(sess)
				close(done)
			}()
			runSendingPeer(sess)
			<-done
			close(done1)
		}()

		client, err := quic.DialAddr(
			serverAddr,
			getTLSClientConfig(),
			qconf,
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
