package self_test

import (
	"context"
	"fmt"
	"io/ioutil"
	"net"
	"os"

	quic "github.com/lucas-clemente/quic-go"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Key Update tests", func() {
	var server quic.Listener

	runServer := func() {
		var err error
		// start the server
		server, err = quic.ListenAddr("localhost:0", getTLSConfig(), nil)
		Expect(err).ToNot(HaveOccurred())

		go func() {
			defer GinkgoRecover()
			sess, err := server.Accept(context.Background())
			Expect(err).ToNot(HaveOccurred())
			str, err := sess.OpenUniStream()
			Expect(err).ToNot(HaveOccurred())
			defer str.Close()
			_, err = str.Write(PRDataLong)
			Expect(err).ToNot(HaveOccurred())
		}()
	}

	BeforeEach(func() {
		// update keys as frequently as possible
		os.Setenv("QUIC_GO_KEY_UPDATE_INTERVAL", "1")
		runServer()
	})

	It("downloads a large file", func() {
		sess, err := quic.DialAddr(
			fmt.Sprintf("localhost:%d", server.Addr().(*net.UDPAddr).Port),
			getTLSClientConfig(),
			nil,
		)
		Expect(err).ToNot(HaveOccurred())
		defer sess.Close()
		str, err := sess.AcceptUniStream(context.Background())
		Expect(err).ToNot(HaveOccurred())
		data, err := ioutil.ReadAll(str)
		Expect(err).ToNot(HaveOccurred())
		Expect(data).To(Equal(PRDataLong))
	})
})
