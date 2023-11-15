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

var _ = Describe("Setting the Cipher Suite", func() {
	for _, cs := range []uint16{tls.TLS_AES_128_GCM_SHA256, tls.TLS_CHACHA20_POLY1305_SHA256, tls.TLS_AES_256_GCM_SHA384} {
		cs := cs

		It(fmt.Sprintf("selects %s", tls.CipherSuiteName(cs)), func() {
			reset := SetCipherSuite(cs)
			defer reset()

			ln, err := tls.Listen("tcp4", "localhost:0", testdata.GetTLSConfig())
			Expect(err).ToNot(HaveOccurred())
			defer ln.Close()

			done := make(chan struct{})
			go func() {
				defer GinkgoRecover()
				defer close(done)
				conn, err := ln.Accept()
				Expect(err).ToNot(HaveOccurred())
				_, err = conn.Read(make([]byte, 10))
				Expect(err).ToNot(HaveOccurred())
				Expect(conn.(*tls.Conn).ConnectionState().CipherSuite).To(Equal(cs))
			}()

			conn, err := tls.Dial(
				"tcp4",
				fmt.Sprintf("localhost:%d", ln.Addr().(*net.TCPAddr).Port),
				&tls.Config{RootCAs: testdata.GetRootCA()},
			)
			Expect(err).ToNot(HaveOccurred())
			_, err = conn.Write([]byte("foobar"))
			Expect(err).ToNot(HaveOccurred())
			Expect(conn.ConnectionState().CipherSuite).To(Equal(cs))
			Expect(conn.Close()).To(Succeed())
			Eventually(done).Should(BeClosed())
		})
	}
})
