//go:build go1.21

package qtls

import (
	"crypto/tls"
	"fmt"
	"net"

	"github.com/quic-go/quic-go/internal/testdata"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Client Session Cache", func() {
	It("adds data to and restores data from a session ticket", func() {
		ln, err := tls.Listen("tcp4", "localhost:0", testdata.GetTLSConfig())
		Expect(err).ToNot(HaveOccurred())

		done := make(chan struct{})
		go func() {
			defer GinkgoRecover()
			defer close(done)

			for {
				conn, err := ln.Accept()
				if err != nil {
					return
				}
				_, err = conn.Read(make([]byte, 10))
				Expect(err).ToNot(HaveOccurred())
				_, err = conn.Write([]byte("foobar"))
				Expect(err).ToNot(HaveOccurred())
			}
		}()

		restored := make(chan []byte, 1)
		clientConf := &tls.Config{
			RootCAs: testdata.GetRootCA(),
			ClientSessionCache: &clientSessionCache{
				wrapped: tls.NewLRUClientSessionCache(10),
				getData: func() []byte { return []byte("session") },
				setData: func(data []byte) { restored <- data },
			},
		}
		conn, err := tls.Dial(
			"tcp4",
			fmt.Sprintf("localhost:%d", ln.Addr().(*net.TCPAddr).Port),
			clientConf,
		)
		Expect(err).ToNot(HaveOccurred())
		_, err = conn.Write([]byte("foobar"))
		Expect(err).ToNot(HaveOccurred())
		Expect(conn.ConnectionState().DidResume).To(BeFalse())
		Expect(restored).To(HaveLen(0))
		_, err = conn.Read(make([]byte, 10))
		Expect(err).ToNot(HaveOccurred())
		Expect(conn.Close()).To(Succeed())

		// make sure the cache can deal with nonsensical inputs
		clientConf.ClientSessionCache.Put("foo", nil)
		clientConf.ClientSessionCache.Put("bar", &tls.ClientSessionState{})

		conn, err = tls.Dial(
			"tcp4",
			fmt.Sprintf("localhost:%d", ln.Addr().(*net.TCPAddr).Port),
			clientConf,
		)
		Expect(err).ToNot(HaveOccurred())
		_, err = conn.Write([]byte("foobar"))
		Expect(err).ToNot(HaveOccurred())
		Expect(conn.ConnectionState().DidResume).To(BeTrue())
		var restoredData []byte
		Expect(restored).To(Receive(&restoredData))
		Expect(restoredData).To(Equal([]byte("session")))
		Expect(conn.Close()).To(Succeed())

		Expect(ln.Close()).To(Succeed())
		Eventually(done).Should(BeClosed())
	})
})
