package self_test

import (
	"crypto/tls"
	"fmt"
	"io"
	"io/ioutil"
	"sync"

	"github.com/lucas-clemente/quic-go/integrationtests/tools/testserver"

	quic "github.com/lucas-clemente/quic-go"
	"github.com/lucas-clemente/quic-go/internal/testdata"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Stream tests", func() {
	var server quic.Listener
	const numStreams = 300

	BeforeEach(func() {
		var err error
		server, err = quic.ListenAddr("localhost:0", testdata.GetTLSConfig(), nil)
		Expect(err).ToNot(HaveOccurred())
	})

	AfterEach(func() {
		server.Close()
	})

	runSendingPeer := func(sess quic.Session) {
		var wg sync.WaitGroup
		wg.Add(numStreams)
		for i := 0; i < numStreams; i++ {
			str, err := sess.OpenStreamSync()
			Expect(err).ToNot(HaveOccurred())
			data := testserver.GeneratePRData(25 * i)
			go func() {
				defer GinkgoRecover()
				_, err := str.Write(data)
				Expect(err).ToNot(HaveOccurred())
				Expect(str.Close()).To(Succeed())
			}()
			go func() {
				defer GinkgoRecover()
				defer wg.Done()
				dataRead, err := ioutil.ReadAll(str)
				Expect(err).ToNot(HaveOccurred())
				Expect(dataRead).To(Equal(data))
			}()
		}
		wg.Wait()
	}

	runReceivingPeer := func(sess quic.Session) {
		var wg sync.WaitGroup
		wg.Add(numStreams)
		for i := 0; i < numStreams; i++ {
			str, err := sess.AcceptStream()
			Expect(err).ToNot(HaveOccurred())
			go func() {
				defer GinkgoRecover()
				defer wg.Done()
				_, err := io.Copy(str, str)
				Expect(err).ToNot(HaveOccurred())
				Expect(str.Close()).To(Succeed())
			}()
		}
		wg.Wait()
	}

	It(fmt.Sprintf("client opening %d streams to a client", numStreams), func() {
		done := make(chan struct{})
		go func() {
			defer GinkgoRecover()
			sess, err := server.Accept()
			Expect(err).ToNot(HaveOccurred())
			runReceivingPeer(sess)
			close(done)
		}()

		client, err := quic.DialAddr(server.Addr().String(), &tls.Config{InsecureSkipVerify: true}, nil)
		Expect(err).ToNot(HaveOccurred())
		runSendingPeer(client)
		<-done
	})

	It(fmt.Sprintf("server opening %d streams to a client", numStreams), func() {
		done := make(chan struct{})
		go func() {
			defer GinkgoRecover()
			sess, err := server.Accept()
			Expect(err).ToNot(HaveOccurred())
			runSendingPeer(sess)
			close(done)
		}()

		client, err := quic.DialAddr(server.Addr().String(), &tls.Config{InsecureSkipVerify: true}, nil)
		Expect(err).ToNot(HaveOccurred())
		runReceivingPeer(client)
		<-done
	})

	It(fmt.Sprintf("client and server opening %d each and sending data to the peer", numStreams), func() {
		done1 := make(chan struct{})
		go func() {
			defer GinkgoRecover()
			sess, err := server.Accept()
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

		client, err := quic.DialAddr(server.Addr().String(), &tls.Config{InsecureSkipVerify: true}, nil)
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
