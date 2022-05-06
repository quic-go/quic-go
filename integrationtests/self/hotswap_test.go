package self_test

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/lucas-clemente/quic-go"
	"github.com/lucas-clemente/quic-go/http3"
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/testdata"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/gbytes"
)

type listenerWrapper struct {
	quic.EarlyListener
	listenerClosed bool
	count          int32
}

func (ln *listenerWrapper) Close() error {
	ln.listenerClosed = true
	return ln.EarlyListener.Close()
}

func (ln *listenerWrapper) Faker() *fakeClosingListener {
	atomic.AddInt32(&ln.count, 1)
	return &fakeClosingListener{listenerWrapper: ln}
}

type fakeClosingListener struct {
	*listenerWrapper
	mu     sync.Mutex
	closed bool
	cancel context.CancelFunc
}

func (ln *fakeClosingListener) Accept(ctx context.Context) (quic.EarlyConnection, error) {
	ln.mu.Lock()
	if ln.closed {
		ln.mu.Unlock()
		return nil, quic.ErrServerClosed
	}

	// NB we assume that Accept will not be called concurrently.
	Expect(ln.cancel).To(BeNil())

	ctx, cancel := context.WithCancel(ctx)
	ln.cancel = cancel

	ln.mu.Unlock()

	c, err := ln.listenerWrapper.Accept(ctx)

	ln.mu.Lock()
	ln.cancel()
	ln.cancel = nil
	ln.mu.Unlock()

	return c, err
}

func (ln *fakeClosingListener) Close() error {
	ln.mu.Lock()
	defer ln.mu.Unlock()
	if ln.closed {
		return nil
	}
	ln.closed = true
	if ln.cancel != nil {
		ln.cancel()
	}
	if atomic.AddInt32(&ln.listenerWrapper.count, -1) == 0 {
		ln.listenerWrapper.Close()
	}
	return nil
}

var _ = Describe("HTTP3 Server hotswap test", func() {
	var (
		mux1    *http.ServeMux
		mux2    *http.ServeMux
		client  *http.Client
		server1 *http3.Server
		server2 *http3.Server
		ln      *listenerWrapper
		port    string
	)

	versions := protocol.SupportedVersions

	BeforeEach(func() {
		mux1 = http.NewServeMux()
		mux1.HandleFunc("/hello1", func(w http.ResponseWriter, r *http.Request) {
			defer GinkgoRecover()
			io.WriteString(w, "Hello, World 1!\n") // don't check the error here. Stream may be reset.
		})

		mux2 = http.NewServeMux()
		mux2.HandleFunc("/hello2", func(w http.ResponseWriter, r *http.Request) {
			defer GinkgoRecover()
			io.WriteString(w, "Hello, World 2!\n") // don't check the error here. Stream may be reset.
		})

		server1 = &http3.Server{
			Server: &http.Server{
				Handler:   mux1,
				TLSConfig: testdata.GetTLSConfig(),
			},
			QuicConfig: getQuicConfig(&quic.Config{Versions: versions}),
		}

		server2 = &http3.Server{
			Server: &http.Server{
				Handler:   mux2,
				TLSConfig: testdata.GetTLSConfig(),
			},
			QuicConfig: getQuicConfig(&quic.Config{Versions: versions}),
		}

		tlsConf := http3.ConfigureTLSConfig(testdata.GetTLSConfig())
		quicln, err := quic.ListenAddrEarly("0.0.0.0:0", tlsConf, getQuicConfig(&quic.Config{Versions: versions}))
		ln = &listenerWrapper{EarlyListener: quicln}
		Expect(err).NotTo(HaveOccurred())
		port = strconv.Itoa(ln.Addr().(*net.UDPAddr).Port)
	})

	AfterEach(func() {
		Expect(ln.Close()).NotTo(HaveOccurred())
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
					},
				}
			})

			It("hotswap works", func() {
				// open first server and make single request to it
				fake1 := ln.Faker()
				stoppedServing1 := make(chan struct{})
				go func() {
					defer GinkgoRecover()
					server1.ServeListener(fake1)
					close(stoppedServing1)
				}()

				resp, err := client.Get("https://localhost:" + port + "/hello1")
				Expect(err).ToNot(HaveOccurred())
				Expect(resp.StatusCode).To(Equal(200))
				body, err := io.ReadAll(gbytes.TimeoutReader(resp.Body, 3*time.Second))
				Expect(err).ToNot(HaveOccurred())
				Expect(string(body)).To(Equal("Hello, World 1!\n"))

				// open second server with same underlying listener,
				// make sure it opened and both servers are currently running
				fake2 := ln.Faker()
				stoppedServing2 := make(chan struct{})
				go func() {
					defer GinkgoRecover()
					server2.ServeListener(fake2)
					close(stoppedServing2)
				}()

				Consistently(stoppedServing1).ShouldNot(BeClosed())
				Consistently(stoppedServing2).ShouldNot(BeClosed())

				// now close first server, no errors should occur here
				// and only the fake listener should be closed
				Expect(server1.Close()).NotTo(HaveOccurred())
				Eventually(stoppedServing1).Should(BeClosed())
				Expect(fake1.closed).To(BeTrue())
				Expect(fake2.closed).To(BeFalse())
				Expect(ln.listenerClosed).ToNot(BeTrue())
				Expect(client.Transport.(*http3.RoundTripper).Close()).NotTo(HaveOccurred())

				// verify that new connections are being initiated from the second server now
				resp, err = client.Get("https://localhost:" + port + "/hello2")
				Expect(err).ToNot(HaveOccurred())
				Expect(resp.StatusCode).To(Equal(200))
				body, err = io.ReadAll(gbytes.TimeoutReader(resp.Body, 3*time.Second))
				Expect(err).ToNot(HaveOccurred())
				Expect(string(body)).To(Equal("Hello, World 2!\n"))

				// close the other server - both the fake and the actual listeners must close now
				Expect(server2.Close()).NotTo(HaveOccurred())
				Eventually(stoppedServing2).Should(BeClosed())
				Expect(fake2.closed).To(BeTrue())
				Expect(ln.listenerClosed).To(BeTrue())
			})
		})
	}
})
