package self_test

import (
	"crypto/tls"
	"fmt"
	"net"
	"time"

	quic "github.com/lucas-clemente/quic-go"
	quicproxy "github.com/lucas-clemente/quic-go/integrationtests/tools/proxy"
	"github.com/lucas-clemente/quic-go/internal/testdata"
	"github.com/lucas-clemente/quic-go/internal/utils"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Timeout tests", func() {
	checkTimeoutError := func(err error) {
		ExpectWithOffset(1, err).To(HaveOccurred())
		nerr, ok := err.(net.Error)
		ExpectWithOffset(1, ok).To(BeTrue())
		ExpectWithOffset(1, nerr.Timeout()).To(BeTrue())
	}

	It("returns net.Error timeout errors when an idle timeout occurs", func() {
		const idleTimeout = 100 * time.Millisecond

		server, err := quic.ListenAddr(
			"localhost:0",
			testdata.GetTLSConfig(),
			nil,
		)
		Expect(err).ToNot(HaveOccurred())
		defer server.Close()

		go func() {
			defer GinkgoRecover()
			sess, err := server.Accept()
			Expect(err).ToNot(HaveOccurred())
			str, err := sess.OpenStream()
			Expect(err).ToNot(HaveOccurred())
			_, err = str.Write([]byte("foobar"))
			Expect(err).ToNot(HaveOccurred())
		}()

		drop := utils.AtomicBool{}

		proxy, err := quicproxy.NewQuicProxy("localhost:0", &quicproxy.Opts{
			RemoteAddr: fmt.Sprintf("localhost:%d", server.Addr().(*net.UDPAddr).Port),
			DropPacket: func(d quicproxy.Direction, p uint64) bool {
				return drop.Get()
			},
		})
		Expect(err).ToNot(HaveOccurred())
		defer proxy.Close()

		sess, err := quic.DialAddr(
			fmt.Sprintf("localhost:%d", proxy.LocalPort()),
			&tls.Config{RootCAs: testdata.GetRootCA()},
			&quic.Config{IdleTimeout: idleTimeout},
		)
		Expect(err).ToNot(HaveOccurred())
		strIn, err := sess.AcceptStream()
		Expect(err).ToNot(HaveOccurred())
		strOut, err := sess.OpenStream()
		Expect(err).ToNot(HaveOccurred())
		_, err = strIn.Read(make([]byte, 6))
		Expect(err).ToNot(HaveOccurred())

		drop.Set(true)
		time.Sleep(2 * idleTimeout)
		_, err = strIn.Write([]byte("test"))
		checkTimeoutError(err)
		_, err = strIn.Read([]byte{0})
		checkTimeoutError(err)
		_, err = strOut.Write([]byte("test"))
		checkTimeoutError(err)
		_, err = strOut.Read([]byte{0})
		checkTimeoutError(err)
		_, err = sess.OpenStream()
		checkTimeoutError(err)
		_, err = sess.OpenUniStream()
		checkTimeoutError(err)
		_, err = sess.AcceptStream()
		checkTimeoutError(err)
		_, err = sess.AcceptUniStream()
		checkTimeoutError(err)
	})
})
