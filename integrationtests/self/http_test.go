package self_test

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"strconv"
	"time"

	quic "github.com/lucas-clemente/quic-go"
	"github.com/lucas-clemente/quic-go/http3"
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/testdata"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/gbytes"
)

type streamCancelError interface {
	Canceled() bool
	ErrorCode() protocol.ApplicationErrorCode
}

var _ = Describe("HTTP tests", func() {
	var (
		mux            *http.ServeMux
		client         *http.Client
		server         *http3.Server
		stoppedServing chan struct{}
		port           string
	)

	versions := protocol.SupportedVersions

	BeforeEach(func() {
		mux = http.NewServeMux()
		mux.HandleFunc("/hello", func(w http.ResponseWriter, r *http.Request) {
			defer GinkgoRecover()
			io.WriteString(w, "Hello, World!\n") // don't check the error here. Stream may be reset.
		})

		mux.HandleFunc("/prdata", func(w http.ResponseWriter, r *http.Request) {
			defer GinkgoRecover()
			sl := r.URL.Query().Get("len")
			if sl != "" {
				var err error
				l, err := strconv.Atoi(sl)
				Expect(err).NotTo(HaveOccurred())
				w.Write(GeneratePRData(l)) // don't check the error here. Stream may be reset.
			} else {
				w.Write(PRData) // don't check the error here. Stream may be reset.
			}
		})

		mux.HandleFunc("/prdatalong", func(w http.ResponseWriter, r *http.Request) {
			defer GinkgoRecover()
			w.Write(PRDataLong) // don't check the error here. Stream may be reset.
		})

		mux.HandleFunc("/echo", func(w http.ResponseWriter, r *http.Request) {
			defer GinkgoRecover()
			body, err := ioutil.ReadAll(r.Body)
			Expect(err).NotTo(HaveOccurred())
			w.Write(body) // don't check the error here. Stream may be reset.
		})

		server = &http3.Server{
			Server: &http.Server{
				Handler:   mux,
				TLSConfig: testdata.GetTLSConfig(),
			},
			QuicConfig: &quic.Config{Versions: versions},
		}

		addr, err := net.ResolveUDPAddr("udp", "0.0.0.0:0")
		Expect(err).NotTo(HaveOccurred())
		conn, err := net.ListenUDP("udp", addr)
		Expect(err).NotTo(HaveOccurred())
		port = strconv.Itoa(conn.LocalAddr().(*net.UDPAddr).Port)

		stoppedServing = make(chan struct{})

		go func() {
			defer GinkgoRecover()
			server.Serve(conn)
			close(stoppedServing)
		}()
	})

	AfterEach(func() {
		Expect(server.Close()).NotTo(HaveOccurred())
		Eventually(stoppedServing).Should(BeClosed())
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
				resp, err := client.Get("https://localhost:" + port + "/hello")
				Expect(err).ToNot(HaveOccurred())
				Expect(resp.StatusCode).To(Equal(200))
				body, err := ioutil.ReadAll(gbytes.TimeoutReader(resp.Body, 3*time.Second))
				Expect(err).ToNot(HaveOccurred())
				Expect(string(body)).To(Equal("Hello, World!\n"))
			})

			It("sets and gets request headers", func() {
				handlerCalled := make(chan struct{})
				mux.HandleFunc("/headers/request", func(w http.ResponseWriter, r *http.Request) {
					defer GinkgoRecover()
					Expect(r.Header.Get("foo")).To(Equal("bar"))
					Expect(r.Header.Get("lorem")).To(Equal("ipsum"))
					close(handlerCalled)
				})

				req, err := http.NewRequest(http.MethodGet, "https://localhost:"+port+"/headers/request", nil)
				Expect(err).ToNot(HaveOccurred())
				req.Header.Set("foo", "bar")
				req.Header.Set("lorem", "ipsum")
				resp, err := client.Do(req)
				Expect(err).ToNot(HaveOccurred())
				Expect(resp.StatusCode).To(Equal(200))
				Eventually(handlerCalled).Should(BeClosed())
			})

			It("sets and gets response headers", func() {
				mux.HandleFunc("/headers/response", func(w http.ResponseWriter, r *http.Request) {
					defer GinkgoRecover()
					w.Header().Set("foo", "bar")
					w.Header().Set("lorem", "ipsum")
				})

				resp, err := client.Get("https://localhost:" + port + "/headers/response")
				Expect(err).ToNot(HaveOccurred())
				Expect(resp.StatusCode).To(Equal(200))
				Expect(resp.Header.Get("foo")).To(Equal("bar"))
				Expect(resp.Header.Get("lorem")).To(Equal("ipsum"))
			})

			It("downloads a small file", func() {
				resp, err := client.Get("https://localhost:" + port + "/prdata")
				Expect(err).ToNot(HaveOccurred())
				Expect(resp.StatusCode).To(Equal(200))
				body, err := ioutil.ReadAll(gbytes.TimeoutReader(resp.Body, 5*time.Second))
				Expect(err).ToNot(HaveOccurred())
				Expect(body).To(Equal(PRData))
			})

			It("downloads a large file", func() {
				resp, err := client.Get("https://localhost:" + port + "/prdatalong")
				Expect(err).ToNot(HaveOccurred())
				Expect(resp.StatusCode).To(Equal(200))
				body, err := ioutil.ReadAll(gbytes.TimeoutReader(resp.Body, 20*time.Second))
				Expect(err).ToNot(HaveOccurred())
				Expect(body).To(Equal(PRDataLong))
			})

			It("downloads many hellos", func() {
				const num = 150

				for i := 0; i < num; i++ {
					resp, err := client.Get("https://localhost:" + port + "/hello")
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
					resp, err := client.Get("https://localhost:" + port + "/prdata")
					Expect(err).ToNot(HaveOccurred())
					Expect(resp.StatusCode).To(Equal(200))
					Expect(resp.Body.Close()).To(Succeed())
				}
			})

			It("posts a small message", func() {
				resp, err := client.Post(
					"https://localhost:"+port+"/echo",
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
					"https://localhost:"+port+"/echo",
					"text/plain",
					bytes.NewReader(PRData),
				)
				Expect(err).ToNot(HaveOccurred())
				Expect(resp.StatusCode).To(Equal(200))
				body, err := ioutil.ReadAll(gbytes.TimeoutReader(resp.Body, 5*time.Second))
				Expect(err).ToNot(HaveOccurred())
				Expect(body).To(Equal(PRData))
			})

			It("uses gzip compression", func() {
				mux.HandleFunc("/gzipped/hello", func(w http.ResponseWriter, r *http.Request) {
					defer GinkgoRecover()
					Expect(r.Header.Get("Accept-Encoding")).To(Equal("gzip"))
					w.Header().Set("Content-Encoding", "gzip")
					w.Header().Set("foo", "bar")

					gw := gzip.NewWriter(w)
					defer gw.Close()
					gw.Write([]byte("Hello, World!\n"))
				})

				client.Transport.(*http3.RoundTripper).DisableCompression = false
				resp, err := client.Get("https://localhost:" + port + "/gzipped/hello")
				Expect(err).ToNot(HaveOccurred())
				Expect(resp.StatusCode).To(Equal(200))
				Expect(resp.Uncompressed).To(BeTrue())

				body, err := ioutil.ReadAll(gbytes.TimeoutReader(resp.Body, 3*time.Second))
				Expect(err).ToNot(HaveOccurred())
				Expect(string(body)).To(Equal("Hello, World!\n"))
			})

			It("cancels requests", func() {
				handlerCalled := make(chan struct{})
				mux.HandleFunc("/cancel", func(w http.ResponseWriter, r *http.Request) {
					defer GinkgoRecover()
					defer close(handlerCalled)
					for {
						if _, err := w.Write([]byte("foobar")); err != nil {
							Expect(r.Context().Done()).To(BeClosed())
							serr, ok := err.(streamCancelError)
							Expect(ok).To(BeTrue())
							Expect(serr.Canceled()).To(BeTrue())
							Expect(serr.ErrorCode()).To(BeEquivalentTo(0x10c))
							return
						}
					}
				})

				req, err := http.NewRequest(http.MethodGet, "https://localhost:"+port+"/cancel", nil)
				Expect(err).ToNot(HaveOccurred())
				ctx, cancel := context.WithCancel(context.Background())
				req = req.WithContext(ctx)
				resp, err := client.Do(req)
				Expect(err).ToNot(HaveOccurred())
				Expect(resp.StatusCode).To(Equal(200))
				cancel()
				Eventually(handlerCalled).Should(BeClosed())
				_, err = resp.Body.Read([]byte{0})
				Expect(err).To(HaveOccurred())
			})
		})
	}
})
