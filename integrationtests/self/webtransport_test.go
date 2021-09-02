package self_test

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/lucas-clemente/quic-go"
	"github.com/lucas-clemente/quic-go/http3"
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/testdata"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("WebTransport tests", func() {
	var (
		client          *http.Client
		server          *http3.Server
		incomingStrings chan string
		stoppedServing  chan struct{}
		port            string
	)

	versions := protocol.SupportedVersions

	webTransportRequest := func(path string) (*http.Request, error) {
		req, err := http.NewRequest(http.MethodConnect, "https://localhost:"+port+path, nil)
		if err != nil {
			return nil, err
		}
		// req.Proto = "HTTP/3"
		// req.ProtoMajor = 3
		// req.ProtoMinor = 0
		req.Header[":protocol"] = []string{"WebTransport"}
		return req, nil
	}

	BeforeEach(func() {
		handler := func(rw http.ResponseWriter, req *http.Request) {
			defer GinkgoRecover()
			rw.WriteHeader(http.StatusOK)
			if flusher, ok := rw.(http.Flusher); ok {
				flusher.Flush() // Required to send headers
			}
			var wt http3.WebTransport
			if wtb, ok := req.Body.(http3.WebTransporter); ok {
				var err error
				wt, err = wtb.WebTransport()
				if err != nil {
					rw.WriteHeader(http.StatusInternalServerError)
					return
				}
			}
			if wt == nil {
				panic("unable to get WebTransport interface")
			}
			ctx := req.Context()

			// Handle incoming unidirectional streams
			go func() {
				defer GinkgoRecover()
				for {
					str, err := wt.AcceptUniStream(ctx)
					if err != nil {
						return
					}
					go func(str quic.ReceiveStream) {
						defer GinkgoRecover()
						r := bufio.NewReader(str)
						for {
							s, err := r.ReadString('\n')
							if err != nil {
								return
							}
							incomingStrings <- s
						}
					}(str)
				}
			}()

			// Handle incoming datagrams
			go func() {
				defer GinkgoRecover()
				for {
					s, err := wt.ReadDatagram(ctx)
					if err != nil {
						return
					}
					err = wt.WriteDatagram(s)
					if err != nil {
						return
					}
				}
			}()

			// Handle incoming bidirectional streams
			go func() {
				defer GinkgoRecover()
				for {
					str, err := wt.AcceptStream(ctx)
					if err != nil {
						return
					}
					go func(str quic.Stream) {
						defer GinkgoRecover()
						defer str.Close()
						r := bufio.NewReader(str)
						for {
							s, err := r.ReadString('\n')
							if err != nil {
								return
							}
							_, err = str.Write([]byte(s))
							if err != nil {
								return
							}
						}
					}(str)
				}
			}()

			// Process other incoming HTTP/3 frames
			io.ReadAll(req.Body)
			req.Body.Close()
		}

		server = &http3.Server{
			Server: &http.Server{
				Handler:   http.HandlerFunc(handler),
				TLSConfig: testdata.GetTLSConfig(),
			},
			QuicConfig:         getQuicConfig(&quic.Config{Versions: versions}),
			EnableDatagrams:    true,
			EnableWebTransport: true,
		}

		addr, err := net.ResolveUDPAddr("udp", "0.0.0.0:0")
		Expect(err).NotTo(HaveOccurred())
		conn, err := net.ListenUDP("udp", addr)
		Expect(err).NotTo(HaveOccurred())
		port = strconv.Itoa(conn.LocalAddr().(*net.UDPAddr).Port)

		incomingStrings = make(chan string)
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
						QuicConfig: getQuicConfig(&quic.Config{
							Versions:       []protocol.VersionNumber{version},
							MaxIdleTimeout: 10 * time.Second,
						}),
						EnableDatagrams:    true,
						EnableWebTransport: true,
					},
				}

				incomingStrings = make(chan string)
			})

			It("can successfully connect to a WebTransport endpoint", func() {
				req, err := webTransportRequest("/")
				Expect(err).ToNot(HaveOccurred())
				res, err := client.Do(req)
				Expect(err).ToNot(HaveOccurred())
				Expect(res.StatusCode).To(Equal(200))
				err = res.Body.Close()
				Expect(err).ToNot(HaveOccurred())
			})

			It("can get a WebTransport client", func() {
				req, err := webTransportRequest("/")
				Expect(err).ToNot(HaveOccurred())
				res, err := client.Do(req)
				Expect(err).ToNot(HaveOccurred())
				Expect(res.StatusCode).To(Equal(200))
				wt, err := res.Body.(http3.WebTransporter).WebTransport()
				Expect(err).ToNot(HaveOccurred())
				Expect(wt).ToNot(BeNil())
				err = wt.Close()
				Expect(err).ToNot(HaveOccurred())
			})

			It("can send data on unidirectional streams", func() {
				req, err := webTransportRequest("/")
				Expect(err).ToNot(HaveOccurred())
				res, err := client.Do(req)
				Expect(err).ToNot(HaveOccurred())
				wt, err := res.Body.(http3.WebTransporter).WebTransport()
				Expect(err).ToNot(HaveOccurred())
				str, err := wt.OpenUniStream()
				Expect(err).ToNot(HaveOccurred())
				for i := 0; i < 5; i++ {
					msg := "Hello, WebTransport!\n"
					_, err := str.Write([]byte(msg))
					Expect(err).ToNot(HaveOccurred())
					Expect(<-incomingStrings).To(Equal(msg))
				}
				err = wt.Close()
				Expect(err).ToNot(HaveOccurred())
			})
		})
	}
})
