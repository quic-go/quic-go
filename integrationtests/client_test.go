package integrationtests

import (
	"io/ioutil"
	"net/http"
	"os"

	"github.com/lucas-clemente/quic-go/h2quic"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Client tests", func() {
	var client *http.Client

	BeforeEach(func() {
		err := os.Setenv("HOSTALIASES", "quic.clemente.io 127.0.0.1")
		Expect(err).ToNot(HaveOccurred())
		client = &http.Client{
			Transport: &h2quic.QuicRoundTripper{},
		}
	})

	It("downloads a hello", func() {
		resp, err := client.Get("https://quic.clemente.io:" + port + "/hello")
		Expect(err).ToNot(HaveOccurred())
		Expect(resp.StatusCode).To(Equal(200))
		body, err := ioutil.ReadAll(resp.Body)
		Expect(err).ToNot(HaveOccurred())
		Expect(string(body)).To(Equal("Hello, World!\n"))
	})

	It("downloads a small file", func() {
		dataMan.GenerateData(dataLen)
		resp, err := client.Get("https://quic.clemente.io:" + port + "/data")
		Expect(err).ToNot(HaveOccurred())
		Expect(resp.StatusCode).To(Equal(200))
		body, err := ioutil.ReadAll(resp.Body)
		Expect(err).ToNot(HaveOccurred())
		Expect(body).To(Equal(dataMan.GetData()))
	})

	It("downloads a large file", func() {
		dataMan.GenerateData(dataLongLen)
		resp, err := client.Get("https://quic.clemente.io:" + port + "/data")
		Expect(err).ToNot(HaveOccurred())
		Expect(resp.StatusCode).To(Equal(200))
		body, err := ioutil.ReadAll(resp.Body)
		Expect(err).ToNot(HaveOccurred())
		Expect(body).To(Equal(dataMan.GetData()))
	})
})
