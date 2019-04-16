package self_test

import (
	"bytes"
	"compress/gzip"
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"

	quic "github.com/lucas-clemente/quic-go"
	"github.com/lucas-clemente/quic-go/http3"
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
					Transport: &http3.RoundTripper{
						TLSClientConfig: &tls.Config{
							RootCAs: testdata.GetRootCA(),
						},
						DisableCompression: true,
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

			It("sets and gets request headers", func() {
				handlerCalled := make(chan struct{})
				http.HandleFunc("/headers/request", func(w http.ResponseWriter, r *http.Request) {
					defer GinkgoRecover()
					Expect(r.Header.Get("foo")).To(Equal("bar"))
					Expect(r.Header.Get("lorem")).To(Equal("ipsum"))
					close(handlerCalled)
				})

				req, err := http.NewRequest(http.MethodGet, "https://localhost:"+testserver.Port()+"/headers/request", nil)
				Expect(err).ToNot(HaveOccurred())
				req.Header.Set("foo", "bar")
				req.Header.Set("lorem", "ipsum")
				resp, err := client.Do(req)
				Expect(err).ToNot(HaveOccurred())
				Expect(resp.StatusCode).To(Equal(200))
				Eventually(handlerCalled).Should(BeClosed())
			})

			It("sets and gets response headers", func() {
				http.HandleFunc("/headers/response", func(w http.ResponseWriter, r *http.Request) {
					defer GinkgoRecover()
					w.Header().Set("foo", "bar")
					w.Header().Set("lorem", "ipsum")
				})

				resp, err := client.Get("https://localhost:" + testserver.Port() + "/headers/response")
				Expect(err).ToNot(HaveOccurred())
				Expect(resp.StatusCode).To(Equal(200))
				Expect(resp.Header.Get("foo")).To(Equal("bar"))
				Expect(resp.Header.Get("lorem")).To(Equal("ipsum"))
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

			It("downloads many hellos", func() {
				const num = 150

				for i := 0; i < num; i++ {
					resp, err := client.Get("https://localhost:" + testserver.Port() + "/hello")
					Expect(err).ToNot(HaveOccurred())
					Expect(resp.StatusCode).To(Equal(200))
					body, err := ioutil.ReadAll(gbytes.TimeoutReader(resp.Body, 3*time.Second))
					Expect(err).ToNot(HaveOccurred())
					Expect(string(body)).To(Equal("Hello, World!\n"))
				}
			})

			It("downloads many files, if the response is not read", func() {
				const num = 150

				for i := 0; i < num; i++ {
					resp, err := client.Get("https://localhost:" + testserver.Port() + "/prdata")
					Expect(err).ToNot(HaveOccurred())
					Expect(resp.StatusCode).To(Equal(200))
					Expect(resp.Body.Close()).To(Succeed())
				}
			})

			It("posts a small message", func() {
				resp, err := client.Post(
					"https://localhost:"+testserver.Port()+"/echo",
					"text/plain",
					bytes.NewReader([]byte("Hello, world!")),
				)
				Expect(err).ToNot(HaveOccurred())
				Expect(resp.StatusCode).To(Equal(200))
				body, err := ioutil.ReadAll(gbytes.TimeoutReader(resp.Body, 5*time.Second))
				Expect(err).ToNot(HaveOccurred())
				Expect(body).To(Equal([]byte("Hello, world!")))
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
				Expect(body).To(Equal(testserver.PRData))
			})

			It("uses gzip compression", func() {
				http.HandleFunc("/gzipped/hello", func(w http.ResponseWriter, r *http.Request) {
					defer GinkgoRecover()
					Expect(r.Header.Get("Accept-Encoding")).To(Equal("gzip"))
					w.Header().Set("Content-Encoding", "gzip")
					w.Header().Set("foo", "bar")

					gw := gzip.NewWriter(w)
					defer gw.Close()
					gw.Write([]byte("Hello, World!\n"))
				})

				client.Transport.(*http3.RoundTripper).DisableCompression = false
				resp, err := client.Get("https://localhost:" + testserver.Port() + "/gzipped/hello")
				Expect(err).ToNot(HaveOccurred())
				Expect(resp.StatusCode).To(Equal(200))
				Expect(resp.Uncompressed).To(BeTrue())

				body, err := ioutil.ReadAll(gbytes.TimeoutReader(resp.Body, 3*time.Second))
				Expect(err).ToNot(HaveOccurred())
				Expect(string(body)).To(Equal("Hello, World!\n"))
			})
		})
	}
})
