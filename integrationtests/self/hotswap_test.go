package self_test

import (
	"context"
	"io"
	"net"
	"net/http"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/gbytes"
)

type listenerWrapper struct {
	http3.QUICEarlyListener
	listenerClosed bool
	count          atomic.Int32
}

func (ln *listenerWrapper) Close() error {
	ln.listenerClosed = true
	return ln.QUICEarlyListener.Close()
}

func (ln *listenerWrapper) Faker() *fakeClosingListener {
	ln.count.Add(1)
	ctx, cancel := context.WithCancel(context.Background())
	return &fakeClosingListener{
		listenerWrapper: ln,
		ctx:             ctx,
		cancel:          cancel,
	}
}

type fakeClosingListener struct {
	*listenerWrapper
	closed atomic.Bool
	ctx    context.Context
	cancel context.CancelFunc
}

func (ln *fakeClosingListener) Accept(ctx context.Context) (quic.EarlyConnection, error) {
	return ln.listenerWrapper.Accept(ln.ctx)
}

func (ln *fakeClosingListener) Close() error {
	if ln.closed.CompareAndSwap(false, true) {
		ln.cancel()
		if ln.listenerWrapper.count.Add(-1) == 0 {
			ln.listenerWrapper.Close()
		}
	}
	return nil
}

var _ = Describe("HTTP3 Server hotswap test", func() {
	var (
		mux1    *http.ServeMux
		mux2    *http.ServeMux
		client  *http.Client
		rt      *http3.Transport
		server1 *http3.Server
		server2 *http3.Server
		ln      *listenerWrapper
		port    string
	)

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
			Handler:    mux1,
			QUICConfig: getQuicConfig(nil),
		}
		server2 = &http3.Server{
			Handler:    mux2,
			QUICConfig: getQuicConfig(nil),
		}

		tlsConf := http3.ConfigureTLSConfig(getTLSConfig())
		quicln, err := quic.ListenAddrEarly("0.0.0.0:0", tlsConf, getQuicConfig(nil))
		ln = &listenerWrapper{QUICEarlyListener: quicln}
		Expect(err).NotTo(HaveOccurred())
		port = strconv.Itoa(ln.Addr().(*net.UDPAddr).Port)
	})

	AfterEach(func() {
		Expect(rt.Close()).NotTo(HaveOccurred())
		Expect(ln.Close()).NotTo(HaveOccurred())
	})

	BeforeEach(func() {
		rt = &http3.Transport{
			TLSClientConfig:    getTLSClientConfig(),
			DisableCompression: true,
			QUICConfig:         getQuicConfig(&quic.Config{MaxIdleTimeout: 10 * time.Second}),
		}
		client = &http.Client{Transport: rt}
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
		Expect(fake1.closed.Load()).To(BeTrue())
		Expect(fake2.closed.Load()).To(BeFalse())
		Expect(ln.listenerClosed).ToNot(BeTrue())
		Expect(client.Transport.(*http3.Transport).Close()).NotTo(HaveOccurred())

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
		Expect(fake2.closed.Load()).To(BeTrue())
		Expect(ln.listenerClosed).To(BeTrue())
	})
})
