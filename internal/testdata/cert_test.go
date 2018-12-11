package testdata

import (
	"crypto/tls"
	"io/ioutil"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("certificates", func() {
	It("returns certificates", func() {
		ln, err := tls.Listen("tcp", "localhost:4433", GetTLSConfig())
		Expect(err).ToNot(HaveOccurred())

		go func() {
			defer GinkgoRecover()
			conn, err := ln.Accept()
			Expect(err).ToNot(HaveOccurred())
			defer conn.Close()
			_, err = conn.Write([]byte("foobar"))
			Expect(err).ToNot(HaveOccurred())
		}()

		conn, err := tls.Dial("tcp", "localhost:4433", &tls.Config{RootCAs: GetRootCA()})
		Expect(err).ToNot(HaveOccurred())
		data, err := ioutil.ReadAll(conn)
		Expect(err).ToNot(HaveOccurred())
		Expect(string(data)).To(Equal("foobar"))
	})
})
