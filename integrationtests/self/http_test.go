package self_test

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"

	quic "github.com/lucas-clemente/quic-go"
	"github.com/lucas-clemente/quic-go/h2quic"
	"github.com/lucas-clemente/quic-go/integrationtests/tools/testserver"
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/testdata"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/gbytes"
)

var _ = Describe("HTTP tests", func() {
	var client *http.Client

	versions := protocol.SupportedVersions

	BeforeEach(func() {
		testserver.StartQuicServer(versions)
	})

	AfterEach(func() {
		testserver.StopQuicServer()
	})

	for _, v := range versions {
		version := v

		Context(fmt.Sprintf("with QUIC version %s", version), func() {
			BeforeEach(func() {
				client = &http.Client{
					Transport: &h2quic.RoundTripper{
						TLSClientConfig: &tls.Config{
							RootCAs: testdata.GetRootCA(),
						},
						QuicConfig: &quic.Config{
							Versions:    []protocol.VersionNumber{version},
							IdleTimeout: 10 * time.Second,
						},
					},
				}
			})

			It("downloads a hello", func() {
				resp, err := client.Get("https://localhost:" + testserver.Port() + "/hello")
				Expect(err).ToNot(HaveOccurred())
				Expect(resp.StatusCode).To(Equal(200))
				body, err := ioutil.ReadAll(gbytes.TimeoutReader(resp.Body, 3*time.Second))
				Expect(err).ToNot(HaveOccurred())
				Expect(string(body)).To(Equal("Hello, World!\n"))
			})

			It("downloads a small file", func() {
				resp, err := client.Get("https://localhost:" + testserver.Port() + "/prdata")
				Expect(err).ToNot(HaveOccurred())
				Expect(resp.StatusCode).To(Equal(200))
				body, err := ioutil.ReadAll(gbytes.TimeoutReader(resp.Body, 5*time.Second))
				Expect(err).ToNot(HaveOccurred())
				Expect(body).To(Equal(testserver.PRData))
			})

			It("downloads a large file", func() {
				resp, err := client.Get("https://localhost:" + testserver.Port() + "/prdatalong")
				Expect(err).ToNot(HaveOccurred())
				Expect(resp.StatusCode).To(Equal(200))
				body, err := ioutil.ReadAll(gbytes.TimeoutReader(resp.Body, 20*time.Second))
				Expect(err).ToNot(HaveOccurred())
				Expect(body).To(Equal(testserver.PRDataLong))
			})

			// TODO(#1756): this test times out
			PIt("downloads many files, if the response is not read", func() {
				const num = 150

				for i := 0; i < num; i++ {
					resp, err := client.Get("https://localhost:" + testserver.Port() + "/prdata")
					Expect(err).ToNot(HaveOccurred())
					Expect(resp.StatusCode).To(Equal(200))
					Expect(resp.Body.Close()).To(Succeed())
				}
			})

			It("uploads a file", func() {
				resp, err := client.Post(
					"https://localhost:"+testserver.Port()+"/echo",
					"text/plain",
					bytes.NewReader(testserver.PRData),
				)
				Expect(err).ToNot(HaveOccurred())
				Expect(resp.StatusCode).To(Equal(200))
				body, err := ioutil.ReadAll(gbytes.TimeoutReader(resp.Body, 5*time.Second))
				Expect(err).ToNot(HaveOccurred())
				Expect(bytes.Equal(body, testserver.PRData)).To(BeTrue())
			})
		})
	}
})
