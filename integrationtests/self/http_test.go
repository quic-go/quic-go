package self_test

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/textproto"
	"net/url"
	"os"
	"strconv"
	"sync/atomic"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	quicproxy "github.com/quic-go/quic-go/integrationtests/tools/proxy"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/gbytes"
)

type neverEnding byte

func (b neverEnding) Read(p []byte) (n int, err error) {
	for i := range p {
		p[i] = byte(b)
	}
	return len(p), nil
}

const deadlineDelay = 250 * time.Millisecond

var _ = Describe("HTTP tests", func() {
	var (
		mux            *http.ServeMux
		client         *http.Client
		rt             *http3.RoundTripper
		server         *http3.Server
		stoppedServing chan struct{}
		port           int
	)

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
			body, err := io.ReadAll(r.Body)
			Expect(err).NotTo(HaveOccurred())
			w.Write(body) // don't check the error here. Stream may be reset.
		})

		mux.HandleFunc("/remoteAddr", func(w http.ResponseWriter, r *http.Request) {
			defer GinkgoRecover()
			w.Header().Set("X-RemoteAddr", r.RemoteAddr)
			w.WriteHeader(http.StatusOK)
		})

		server = &http3.Server{
			Handler:    mux,
			TLSConfig:  getTLSConfig(),
			QUICConfig: getQuicConfig(&quic.Config{Allow0RTT: true, EnableDatagrams: true}),
		}

		addr, err := net.ResolveUDPAddr("udp", "0.0.0.0:0")
		Expect(err).NotTo(HaveOccurred())
		conn, err := net.ListenUDP("udp", addr)
		Expect(err).NotTo(HaveOccurred())
		port = conn.LocalAddr().(*net.UDPAddr).Port

		stoppedServing = make(chan struct{})

		go func() {
			defer GinkgoRecover()
			server.Serve(conn)
			close(stoppedServing)
		}()
	})

	AfterEach(func() {
		Expect(rt.Close()).NotTo(HaveOccurred())
		Expect(server.Close()).NotTo(HaveOccurred())
		Eventually(stoppedServing).Should(BeClosed())
	})

	BeforeEach(func() {
		rt = &http3.RoundTripper{
			TLSClientConfig: getTLSClientConfigWithoutServerName(),
			QUICConfig: getQuicConfig(&quic.Config{
				MaxIdleTimeout: 10 * time.Second,
			}),
			DisableCompression: true,
		}
		client = &http.Client{Transport: rt}
	})

	It("downloads a hello", func() {
		resp, err := client.Get(fmt.Sprintf("https://localhost:%d/hello", port))
		Expect(err).ToNot(HaveOccurred())
		Expect(resp.StatusCode).To(Equal(200))
		body, err := io.ReadAll(gbytes.TimeoutReader(resp.Body, 3*time.Second))
		Expect(err).ToNot(HaveOccurred())
		Expect(string(body)).To(Equal("Hello, World!\n"))
	})

	It("sets content-length for small response", func() {
		mux.HandleFunc("/small", func(w http.ResponseWriter, r *http.Request) {
			defer GinkgoRecover()
			w.Write([]byte("foo"))
			w.Write([]byte("bar"))
		})

		resp, err := client.Get(fmt.Sprintf("https://localhost:%d/small", port))
		Expect(err).ToNot(HaveOccurred())
		Expect(resp.StatusCode).To(Equal(200))
		Expect(resp.Header.Get("Content-Length")).To(Equal("6"))
	})

	It("re-establishes a QUIC connection after a dial error", func() {
		var dialCounter int
		testErr := errors.New("test error")
		cl := http.Client{
			Transport: &http3.RoundTripper{
				TLSClientConfig: getTLSClientConfig(),
				Dial: func(ctx context.Context, addr string, tlsConf *tls.Config, conf *quic.Config) (quic.EarlyConnection, error) {
					dialCounter++
					if dialCounter == 1 { // make the first dial fail
						return nil, testErr
					}
					return quic.DialAddrEarly(ctx, addr, tlsConf, conf)
				},
			},
		}
		defer cl.Transport.(io.Closer).Close()
		_, err := cl.Get(fmt.Sprintf("https://localhost:%d/hello", port))
		Expect(err).To(MatchError(testErr))
		resp, err := cl.Get(fmt.Sprintf("https://localhost:%d/hello", port))
		Expect(err).ToNot(HaveOccurred())
		Expect(resp.StatusCode).To(Equal(http.StatusOK))
	})

	It("detects stream errors when server panics when writing response", func() {
		respChan := make(chan struct{})
		mux.HandleFunc("/writing_and_panicking", func(w http.ResponseWriter, r *http.Request) {
			// no recover here as it will interfere with the handler
			w.Write([]byte("foobar"))
			w.(http.Flusher).Flush()
			// wait for the client to receive the response
			<-respChan
			panic(http.ErrAbortHandler)
		})

		resp, err := client.Get(fmt.Sprintf("https://localhost:%d/writing_and_panicking", port))
		close(respChan)
		Expect(err).ToNot(HaveOccurred())
		body, err := io.ReadAll(resp.Body)
		Expect(err).To(HaveOccurred())
		// the body will be a prefix of what's written
		Expect(bytes.HasPrefix([]byte("foobar"), body)).To(BeTrue())
	})

	It("requests to different servers with the same udpconn", func() {
		resp, err := client.Get(fmt.Sprintf("https://localhost:%d/remoteAddr", port))
		Expect(err).ToNot(HaveOccurred())
		Expect(resp.StatusCode).To(Equal(200))
		addr1 := resp.Header.Get("X-RemoteAddr")
		Expect(addr1).ToNot(Equal(""))
		resp, err = client.Get(fmt.Sprintf("https://127.0.0.1:%d/remoteAddr", port))
		Expect(err).ToNot(HaveOccurred())
		Expect(resp.StatusCode).To(Equal(200))
		addr2 := resp.Header.Get("X-RemoteAddr")
		Expect(addr2).ToNot(Equal(""))
		Expect(addr1).To(Equal(addr2))
	})

	It("downloads concurrently", func() {
		group, ctx := errgroup.WithContext(context.Background())
		for i := 0; i < 2; i++ {
			group.Go(func() error {
				defer GinkgoRecover()
				req, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("https://localhost:%d/hello", port), nil)
				Expect(err).ToNot(HaveOccurred())
				resp, err := client.Do(req)
				Expect(err).ToNot(HaveOccurred())
				Expect(resp.StatusCode).To(Equal(200))
				body, err := io.ReadAll(gbytes.TimeoutReader(resp.Body, 3*time.Second))
				Expect(err).ToNot(HaveOccurred())
				Expect(string(body)).To(Equal("Hello, World!\n"))

				return nil
			})
		}

		err := group.Wait()
		Expect(err).ToNot(HaveOccurred())
	})

	It("sets and gets request headers", func() {
		handlerCalled := make(chan struct{})
		mux.HandleFunc("/headers/request", func(w http.ResponseWriter, r *http.Request) {
			defer GinkgoRecover()
			Expect(r.Header.Get("foo")).To(Equal("bar"))
			Expect(r.Header.Get("lorem")).To(Equal("ipsum"))
			close(handlerCalled)
		})

		req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("https://localhost:%d/headers/request", port), nil)
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

		resp, err := client.Get(fmt.Sprintf("https://localhost:%d/headers/response", port))
		Expect(err).ToNot(HaveOccurred())
		Expect(resp.StatusCode).To(Equal(200))
		Expect(resp.Header.Get("foo")).To(Equal("bar"))
		Expect(resp.Header.Get("lorem")).To(Equal("ipsum"))
	})

	It("downloads a small file", func() {
		resp, err := client.Get(fmt.Sprintf("https://localhost:%d/prdata", port))
		Expect(err).ToNot(HaveOccurred())
		Expect(resp.StatusCode).To(Equal(200))
		body, err := io.ReadAll(gbytes.TimeoutReader(resp.Body, 5*time.Second))
		Expect(err).ToNot(HaveOccurred())
		Expect(body).To(Equal(PRData))
	})

	It("downloads a large file", func() {
		resp, err := client.Get(fmt.Sprintf("https://localhost:%d/prdatalong", port))
		Expect(err).ToNot(HaveOccurred())
		Expect(resp.StatusCode).To(Equal(200))
		body, err := io.ReadAll(gbytes.TimeoutReader(resp.Body, 20*time.Second))
		Expect(err).ToNot(HaveOccurred())
		Expect(body).To(Equal(PRDataLong))
	})

	It("downloads many hellos", func() {
		const num = 150

		for i := 0; i < num; i++ {
			resp, err := client.Get(fmt.Sprintf("https://localhost:%d/hello", port))
			Expect(err).ToNot(HaveOccurred())
			Expect(resp.StatusCode).To(Equal(200))
			body, err := io.ReadAll(gbytes.TimeoutReader(resp.Body, 3*time.Second))
			Expect(err).ToNot(HaveOccurred())
			Expect(string(body)).To(Equal("Hello, World!\n"))
		}
	})

	It("downloads many files, if the response is not read", func() {
		const num = 150

		for i := 0; i < num; i++ {
			resp, err := client.Get(fmt.Sprintf("https://localhost:%d/prdata", port))
			Expect(err).ToNot(HaveOccurred())
			Expect(resp.StatusCode).To(Equal(200))
			Expect(resp.Body.Close()).To(Succeed())
		}
	})

	It("posts a small message", func() {
		resp, err := client.Post(
			fmt.Sprintf("https://localhost:%d/echo", port),
			"text/plain",
			bytes.NewReader([]byte("Hello, world!")),
		)
		Expect(err).ToNot(HaveOccurred())
		Expect(resp.StatusCode).To(Equal(200))
		body, err := io.ReadAll(gbytes.TimeoutReader(resp.Body, 5*time.Second))
		Expect(err).ToNot(HaveOccurred())
		Expect(body).To(Equal([]byte("Hello, world!")))
	})

	It("uploads a file", func() {
		resp, err := client.Post(
			fmt.Sprintf("https://localhost:%d/echo", port),
			"text/plain",
			bytes.NewReader(PRData),
		)
		Expect(err).ToNot(HaveOccurred())
		Expect(resp.StatusCode).To(Equal(200))
		body, err := io.ReadAll(gbytes.TimeoutReader(resp.Body, 5*time.Second))
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
		resp, err := client.Get(fmt.Sprintf("https://localhost:%d/gzipped/hello", port))
		Expect(err).ToNot(HaveOccurred())
		Expect(resp.StatusCode).To(Equal(200))
		Expect(resp.Uncompressed).To(BeTrue())

		body, err := io.ReadAll(gbytes.TimeoutReader(resp.Body, 3*time.Second))
		Expect(err).ToNot(HaveOccurred())
		Expect(string(body)).To(Equal("Hello, World!\n"))
	})

	It("handles context cancellations", func() {
		mux.HandleFunc("/cancel", func(w http.ResponseWriter, r *http.Request) {
			<-r.Context().Done()
		})

		ctx, cancel := context.WithCancel(context.Background())
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("https://localhost:%d/cancel", port), nil)
		Expect(err).ToNot(HaveOccurred())
		time.AfterFunc(50*time.Millisecond, cancel)

		_, err = client.Do(req)
		Expect(err).To(HaveOccurred())
		Expect(err).To(MatchError(context.Canceled))
	})

	It("cancels requests", func() {
		handlerCalled := make(chan struct{})
		mux.HandleFunc("/cancel", func(w http.ResponseWriter, r *http.Request) {
			defer GinkgoRecover()
			defer close(handlerCalled)
			// TODO(4508): check for request context cancellations
			for {
				if _, err := w.Write([]byte("foobar")); err != nil {
					var http3Err *http3.Error
					Expect(errors.As(err, &http3Err)).To(BeTrue())
					Expect(http3Err.ErrorCode).To(Equal(http3.ErrCode(0x10c)))
					Expect(http3Err.Error()).To(Equal("H3_REQUEST_CANCELLED"))
					return
				}
			}
		})

		req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("https://localhost:%d/cancel", port), nil)
		Expect(err).ToNot(HaveOccurred())
		ctx, cancel := context.WithCancel(context.Background())
		req = req.WithContext(ctx)
		resp, err := client.Do(req)
		Expect(err).ToNot(HaveOccurred())
		Expect(resp.StatusCode).To(Equal(200))
		cancel()
		Eventually(handlerCalled).Should(BeClosed())
		_, err = resp.Body.Read([]byte{0})
		var http3Err *http3.Error
		Expect(errors.As(err, &http3Err)).To(BeTrue())
		Expect(http3Err.ErrorCode).To(Equal(http3.ErrCode(0x10c)))
		Expect(http3Err.Error()).To(Equal("H3_REQUEST_CANCELLED (local)"))
	})

	It("allows streamed HTTP requests", func() {
		done := make(chan struct{})
		mux.HandleFunc("/echoline", func(w http.ResponseWriter, r *http.Request) {
			defer GinkgoRecover()
			defer close(done)
			w.WriteHeader(200)
			w.(http.Flusher).Flush()
			reader := bufio.NewReader(r.Body)
			for {
				msg, err := reader.ReadString('\n')
				if err != nil {
					return
				}
				_, err = w.Write([]byte(msg))
				Expect(err).ToNot(HaveOccurred())
				w.(http.Flusher).Flush()
			}
		})

		r, w := io.Pipe()
		req, err := http.NewRequest(http.MethodPut, fmt.Sprintf("https://localhost:%d/echoline", port), r)
		Expect(err).ToNot(HaveOccurred())
		rsp, err := client.Do(req)
		Expect(err).ToNot(HaveOccurred())
		Expect(rsp.StatusCode).To(Equal(200))

		reader := bufio.NewReader(rsp.Body)
		for i := 0; i < 5; i++ {
			msg := fmt.Sprintf("Hello world, %d!\n", i)
			fmt.Fprint(w, msg)
			msgRcvd, err := reader.ReadString('\n')
			Expect(err).ToNot(HaveOccurred())
			Expect(msgRcvd).To(Equal(msg))
		}
		Expect(req.Body.Close()).To(Succeed())
		Eventually(done).Should(BeClosed())
	})

	It("allows taking over the stream", func() {
		handlerCalled := make(chan struct{})
		mux.HandleFunc("/httpstreamer", func(w http.ResponseWriter, r *http.Request) {
			defer GinkgoRecover()
			close(handlerCalled)
			w.WriteHeader(http.StatusOK)

			str := w.(http3.HTTPStreamer).HTTPStream()
			str.Write([]byte("foobar"))

			// Do this in a Go routine, so that the handler returns early.
			// This way, we can also check that the HTTP/3 doesn't close the stream.
			go func() {
				defer GinkgoRecover()
				_, err := io.Copy(str, str)
				Expect(err).ToNot(HaveOccurred())
				Expect(str.Close()).To(Succeed())
			}()
		})

		req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("https://localhost:%d/httpstreamer", port), nil)
		Expect(err).ToNot(HaveOccurred())
		tlsConf := getTLSClientConfigWithoutServerName()
		tlsConf.NextProtos = []string{http3.NextProtoH3}
		conn, err := quic.DialAddr(
			context.Background(),
			fmt.Sprintf("localhost:%d", port),
			tlsConf,
			getQuicConfig(nil),
		)
		Expect(err).ToNot(HaveOccurred())
		defer conn.CloseWithError(0, "")
		rt := http3.SingleDestinationRoundTripper{Connection: conn}
		str, err := rt.OpenRequestStream(context.Background())
		Expect(err).ToNot(HaveOccurred())
		Expect(str.SendRequestHeader(req)).To(Succeed())
		// make sure the request is received (and not stuck in some buffer, for example)
		Eventually(handlerCalled).Should(BeClosed())

		rsp, err := str.ReadResponse()
		Expect(err).ToNot(HaveOccurred())
		Expect(rsp.StatusCode).To(Equal(200))

		b := make([]byte, 6)
		_, err = io.ReadFull(str, b)
		Expect(err).ToNot(HaveOccurred())
		Expect(b).To(Equal([]byte("foobar")))

		data := GeneratePRData(8 * 1024)
		_, err = str.Write(data)
		Expect(err).ToNot(HaveOccurred())
		Expect(str.Close()).To(Succeed())
		repl, err := io.ReadAll(str)
		Expect(err).ToNot(HaveOccurred())
		Expect(repl).To(Equal(data))
	})

	It("serves QUIC connections", func() {
		tlsConf := getTLSConfig()
		tlsConf.NextProtos = []string{http3.NextProtoH3}
		ln, err := quic.ListenAddr("localhost:0", tlsConf, getQuicConfig(nil))
		Expect(err).ToNot(HaveOccurred())
		defer ln.Close()
		done := make(chan struct{})
		go func() {
			defer GinkgoRecover()
			defer close(done)
			conn, err := ln.Accept(context.Background())
			Expect(err).ToNot(HaveOccurred())
			server.ServeQUICConn(conn) // returns once the client closes
		}()

		resp, err := client.Get(fmt.Sprintf("https://localhost:%d/hello", ln.Addr().(*net.UDPAddr).Port))
		Expect(err).ToNot(HaveOccurred())
		Expect(resp.StatusCode).To(Equal(http.StatusOK))
		client.Transport.(io.Closer).Close()
		Eventually(done).Should(BeClosed())
	})

	It("supports read deadlines", func() {
		mux.HandleFunc("/read-deadline", func(w http.ResponseWriter, r *http.Request) {
			defer GinkgoRecover()
			rc := http.NewResponseController(w)
			Expect(rc.SetReadDeadline(time.Now().Add(deadlineDelay))).To(Succeed())

			body, err := io.ReadAll(r.Body)
			Expect(err).To(MatchError(os.ErrDeadlineExceeded))
			Expect(body).To(ContainSubstring("aa"))

			w.Write([]byte("ok"))
		})

		expectedEnd := time.Now().Add(deadlineDelay)
		resp, err := client.Post(
			fmt.Sprintf("https://localhost:%d/read-deadline", port),
			"text/plain",
			neverEnding('a'),
		)
		Expect(err).ToNot(HaveOccurred())
		Expect(resp.StatusCode).To(Equal(200))

		body, err := io.ReadAll(gbytes.TimeoutReader(resp.Body, 2*deadlineDelay))
		Expect(err).ToNot(HaveOccurred())
		Expect(time.Now().After(expectedEnd)).To(BeTrue())
		Expect(string(body)).To(Equal("ok"))
	})

	It("supports write deadlines", func() {
		mux.HandleFunc("/write-deadline", func(w http.ResponseWriter, r *http.Request) {
			defer GinkgoRecover()
			rc := http.NewResponseController(w)
			Expect(rc.SetWriteDeadline(time.Now().Add(deadlineDelay))).To(Succeed())

			_, err := io.Copy(w, neverEnding('a'))
			Expect(err).To(MatchError(os.ErrDeadlineExceeded))
		})

		expectedEnd := time.Now().Add(deadlineDelay)

		resp, err := client.Get(fmt.Sprintf("https://localhost:%d/write-deadline", port))
		Expect(err).ToNot(HaveOccurred())
		Expect(resp.StatusCode).To(Equal(200))

		body, err := io.ReadAll(gbytes.TimeoutReader(resp.Body, 2*deadlineDelay))
		Expect(err).ToNot(HaveOccurred())
		Expect(time.Now().After(expectedEnd)).To(BeTrue())
		Expect(string(body)).To(ContainSubstring("aa"))
	})

	It("sets remote address", func() {
		mux.HandleFunc("/remote-addr", func(w http.ResponseWriter, r *http.Request) {
			defer GinkgoRecover()
			_, ok := r.Context().Value(http3.RemoteAddrContextKey).(net.Addr)
			Expect(ok).To(BeTrue())
		})

		resp, err := client.Get(fmt.Sprintf("https://localhost:%d/remote-addr", port))
		Expect(err).ToNot(HaveOccurred())
		Expect(resp.StatusCode).To(Equal(200))
	})

	It("sets conn context", func() {
		type ctxKey int
		var tracingID quic.ConnectionTracingID
		server.ConnContext = func(ctx context.Context, c quic.Connection) context.Context {
			serv, ok := ctx.Value(http3.ServerContextKey).(*http3.Server)
			Expect(ok).To(BeTrue())
			Expect(serv).To(Equal(server))

			ctx = context.WithValue(ctx, ctxKey(0), "Hello")
			ctx = context.WithValue(ctx, ctxKey(1), c)
			tracingID = c.Context().Value(quic.ConnectionTracingKey).(quic.ConnectionTracingID)
			return ctx
		}
		mux.HandleFunc("/http3-conn-context", func(w http.ResponseWriter, r *http.Request) {
			defer GinkgoRecover()
			v, ok := r.Context().Value(ctxKey(0)).(string)
			Expect(ok).To(BeTrue())
			Expect(v).To(Equal("Hello"))

			c, ok := r.Context().Value(ctxKey(1)).(quic.Connection)
			Expect(ok).To(BeTrue())
			Expect(c).ToNot(BeNil())

			serv, ok := r.Context().Value(http3.ServerContextKey).(*http3.Server)
			Expect(ok).To(BeTrue())
			Expect(serv).To(Equal(server))

			id, ok := r.Context().Value(quic.ConnectionTracingKey).(quic.ConnectionTracingID)
			Expect(ok).To(BeTrue())
			Expect(id).To(Equal(tracingID))
		})

		resp, err := client.Get(fmt.Sprintf("https://localhost:%d/http3-conn-context", port))
		Expect(err).ToNot(HaveOccurred())
		Expect(resp.StatusCode).To(Equal(http.StatusOK))
	})

	It("uses the QUIC connection context", func() {
		conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
		Expect(err).ToNot(HaveOccurred())
		defer conn.Close()
		tr := &quic.Transport{
			Conn: conn,
			ConnContext: func(ctx context.Context) context.Context {
				//nolint:staticcheck
				return context.WithValue(ctx, "foo", "bar")
			},
		}
		defer tr.Close()
		tlsConf := getTLSConfig()
		tlsConf.NextProtos = []string{http3.NextProtoH3}
		ln, err := tr.Listen(tlsConf, getQuicConfig(nil))
		Expect(err).ToNot(HaveOccurred())
		defer ln.Close()

		mux.HandleFunc("/quic-conn-context", func(w http.ResponseWriter, r *http.Request) {
			defer GinkgoRecover()
			v, ok := r.Context().Value("foo").(string)
			Expect(ok).To(BeTrue())
			Expect(v).To(Equal("bar"))
		})
		go func() {
			defer GinkgoRecover()
			c, err := ln.Accept(context.Background())
			Expect(err).ToNot(HaveOccurred())
			server.ServeQUICConn(c)
		}()

		resp, err := client.Get(fmt.Sprintf("https://localhost:%d/quic-conn-context", conn.LocalAddr().(*net.UDPAddr).Port))
		Expect(err).ToNot(HaveOccurred())
		Expect(resp.StatusCode).To(Equal(http.StatusOK))
	})

	It("checks the server's settings", func() {
		tlsConf := tlsClientConfigWithoutServerName.Clone()
		tlsConf.NextProtos = []string{http3.NextProtoH3}
		conn, err := quic.DialAddr(
			context.Background(),
			fmt.Sprintf("localhost:%d", port),
			tlsConf,
			getQuicConfig(nil),
		)
		Expect(err).ToNot(HaveOccurred())
		defer conn.CloseWithError(0, "")
		rt := http3.SingleDestinationRoundTripper{Connection: conn}
		hconn := rt.Start()
		Eventually(hconn.ReceivedSettings(), 5*time.Second, 10*time.Millisecond).Should(BeClosed())
		settings := hconn.Settings()
		Expect(settings.EnableExtendedConnect).To(BeTrue())
		Expect(settings.EnableDatagrams).To(BeFalse())
		Expect(settings.Other).To(BeEmpty())
	})

	It("receives the client's settings", func() {
		settingsChan := make(chan *http3.Settings, 1)
		mux.HandleFunc("/settings", func(w http.ResponseWriter, r *http.Request) {
			defer GinkgoRecover()
			conn := w.(http3.Hijacker).Connection()
			Eventually(conn.ReceivedSettings(), 5*time.Second, 10*time.Millisecond).Should(BeClosed())
			settingsChan <- conn.Settings()
			w.WriteHeader(http.StatusOK)
		})

		rt = &http3.RoundTripper{
			TLSClientConfig: getTLSClientConfigWithoutServerName(),
			QUICConfig: getQuicConfig(&quic.Config{
				MaxIdleTimeout:  10 * time.Second,
				EnableDatagrams: true,
			}),
			EnableDatagrams:    true,
			AdditionalSettings: map[uint64]uint64{1337: 42},
		}
		req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("https://localhost:%d/settings", port), nil)
		Expect(err).ToNot(HaveOccurred())

		_, err = rt.RoundTrip(req)
		Expect(err).ToNot(HaveOccurred())
		var settings *http3.Settings
		Expect(settingsChan).To(Receive(&settings))
		Expect(settings).ToNot(BeNil())
		Expect(settings.EnableDatagrams).To(BeTrue())
		Expect(settings.EnableExtendedConnect).To(BeFalse())
		Expect(settings.Other).To(HaveKeyWithValue(uint64(1337), uint64(42)))
	})

	It("processes 1xx response", func() {
		header1 := "</style.css>; rel=preload; as=style"
		header2 := "</script.js>; rel=preload; as=script"
		data := "1xx-test-data"
		mux.HandleFunc("/103-early-data", func(w http.ResponseWriter, r *http.Request) {
			defer GinkgoRecover()
			w.Header().Add("Link", header1)
			w.Header().Add("Link", header2)
			w.WriteHeader(http.StatusEarlyHints)
			n, err := w.Write([]byte(data))
			Expect(err).NotTo(HaveOccurred())
			Expect(n).To(Equal(len(data)))
			w.WriteHeader(http.StatusOK)
		})

		var (
			cnt    int
			status int
			hdr    textproto.MIMEHeader
		)
		ctx := httptrace.WithClientTrace(context.Background(), &httptrace.ClientTrace{
			Got1xxResponse: func(code int, header textproto.MIMEHeader) error {
				hdr = header
				status = code
				cnt++
				return nil
			},
		})

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("https://localhost:%d/103-early-data", port), nil)
		Expect(err).ToNot(HaveOccurred())
		resp, err := client.Do(req)
		Expect(err).ToNot(HaveOccurred())
		Expect(resp.StatusCode).To(Equal(http.StatusOK))
		body, err := io.ReadAll(resp.Body)
		Expect(err).ToNot(HaveOccurred())
		Expect(string(body)).To(Equal(data))
		Expect(status).To(Equal(http.StatusEarlyHints))
		Expect(hdr).To(HaveKeyWithValue("Link", []string{header1, header2}))
		Expect(cnt).To(Equal(1))
		Expect(resp.Header).To(HaveKeyWithValue("Link", []string{header1, header2}))
		Expect(resp.Body.Close()).To(Succeed())
	})

	It("processes 1xx terminal response", func() {
		mux.HandleFunc("/101-switch-protocols", func(w http.ResponseWriter, r *http.Request) {
			defer GinkgoRecover()
			w.Header().Add("Connection", "upgrade")
			w.Header().Add("Upgrade", "proto")
			w.WriteHeader(http.StatusSwitchingProtocols)
		})

		var (
			cnt    int
			status int
		)
		ctx := httptrace.WithClientTrace(context.Background(), &httptrace.ClientTrace{
			Got1xxResponse: func(code int, header textproto.MIMEHeader) error {
				status = code
				cnt++
				return nil
			},
		})

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("https://localhost:%d/101-switch-protocols", port), nil)
		Expect(err).ToNot(HaveOccurred())
		resp, err := client.Do(req)
		Expect(err).ToNot(HaveOccurred())
		Expect(resp.StatusCode).To(Equal(http.StatusSwitchingProtocols))
		Expect(resp.Header).To(HaveKeyWithValue("Connection", []string{"upgrade"}))
		Expect(resp.Header).To(HaveKeyWithValue("Upgrade", []string{"proto"}))
		Expect(status).To(Equal(0))
		Expect(cnt).To(Equal(0))
	})

	Context("HTTP datagrams", func() {
		openDatagramStream := func(h string) (_ http3.RequestStream, closeFn func()) {
			tlsConf := getTLSClientConfigWithoutServerName()
			tlsConf.NextProtos = []string{http3.NextProtoH3}
			conn, err := quic.DialAddr(
				context.Background(),
				fmt.Sprintf("localhost:%d", port),
				tlsConf,
				getQuicConfig(&quic.Config{EnableDatagrams: true}),
			)
			Expect(err).ToNot(HaveOccurred())

			rt := &http3.SingleDestinationRoundTripper{
				Connection:      conn,
				EnableDatagrams: true,
			}
			str, err := rt.OpenRequestStream(context.Background())
			Expect(err).ToNot(HaveOccurred())
			u, err := url.Parse(h)
			Expect(err).ToNot(HaveOccurred())
			req := &http.Request{
				Method: http.MethodConnect,
				Proto:  "datagrams",
				Host:   u.Host,
				URL:    u,
			}
			Expect(str.SendRequestHeader(req)).To(Succeed())

			rsp, err := str.ReadResponse()
			Expect(err).ToNot(HaveOccurred())
			Expect(rsp.StatusCode).To(Equal(http.StatusOK))
			return str, func() { conn.CloseWithError(0, "") }
		}

		It("sends an receives HTTP datagrams", func() {
			errChan := make(chan error, 1)
			const num = 5
			datagramChan := make(chan struct{}, num)
			mux.HandleFunc("/datagrams", func(w http.ResponseWriter, r *http.Request) {
				defer GinkgoRecover()
				Expect(r.Method).To(Equal(http.MethodConnect))
				conn := w.(http3.Hijacker).Connection()
				Eventually(conn.ReceivedSettings()).Should(BeClosed())
				Expect(conn.Settings().EnableDatagrams).To(BeTrue())
				w.WriteHeader(http.StatusOK)

				str := w.(http3.HTTPStreamer).HTTPStream()
				go str.Read([]byte{0}) // need to continue reading from stream to observe state transitions

				for {
					if _, err := str.ReceiveDatagram(context.Background()); err != nil {
						errChan <- err
						return
					}
					datagramChan <- struct{}{}
				}
			})

			str, closeFn := openDatagramStream(fmt.Sprintf("https://localhost:%d/datagrams", port))
			defer closeFn()

			for i := 0; i < num; i++ {
				b := make([]byte, 8)
				binary.BigEndian.PutUint64(b, uint64(i))
				Expect(str.SendDatagram(bytes.Repeat(b, 100))).To(Succeed())
			}
			var count int
		loop:
			for {
				select {
				case <-datagramChan:
					count++
					if count >= num*4/5 {
						break loop
					}
				case err := <-errChan:
					Fail(fmt.Sprintf("receiving datagrams failed: %s", err))
				}
			}
			str.CancelWrite(42)

			var resetErr error
			Eventually(errChan).Should(Receive(&resetErr))
			Expect(resetErr.(*quic.StreamError).ErrorCode).To(BeEquivalentTo(42))
		})

		It("closes the send direction", func() {
			errChan := make(chan error, 1)
			datagramChan := make(chan []byte, 1)
			mux.HandleFunc("/datagrams", func(w http.ResponseWriter, r *http.Request) {
				defer GinkgoRecover()
				conn := w.(http3.Hijacker).Connection()
				Eventually(conn.ReceivedSettings()).Should(BeClosed())
				Expect(conn.Settings().EnableDatagrams).To(BeTrue())
				w.WriteHeader(http.StatusOK)

				str := w.(http3.HTTPStreamer).HTTPStream()
				go str.Read([]byte{0}) // need to continue reading from stream to observe state transitions

				for {
					data, err := str.ReceiveDatagram(context.Background())
					if err != nil {
						errChan <- err
						return
					}
					datagramChan <- data
				}
			})

			str, closeFn := openDatagramStream(fmt.Sprintf("https://localhost:%d/datagrams", port))
			defer closeFn()
			go str.Read([]byte{0})

			Expect(str.SendDatagram([]byte("foo"))).To(Succeed())
			Eventually(datagramChan).Should(Receive(Equal([]byte("foo"))))
			// signal that we're done sending
			str.Close()

			var resetErr error
			Eventually(errChan).Should(Receive(&resetErr))
			Expect(resetErr).To(Equal(io.EOF))

			// make sure we can't send anymore
			Expect(str.SendDatagram([]byte("foo"))).ToNot(Succeed())
		})

		It("detecting a stream reset from the server", func() {
			errChan := make(chan error, 1)
			datagramChan := make(chan []byte, 1)
			mux.HandleFunc("/datagrams", func(w http.ResponseWriter, r *http.Request) {
				defer GinkgoRecover()
				conn := w.(http3.Hijacker).Connection()
				Eventually(conn.ReceivedSettings()).Should(BeClosed())
				Expect(conn.Settings().EnableDatagrams).To(BeTrue())
				w.WriteHeader(http.StatusOK)

				str := w.(http3.HTTPStreamer).HTTPStream()
				go str.Read([]byte{0}) // need to continue reading from stream to observe state transitions

				for {
					data, err := str.ReceiveDatagram(context.Background())
					if err != nil {
						errChan <- err
						return
					}
					str.CancelRead(42)
					datagramChan <- data
				}
			})

			str, closeFn := openDatagramStream(fmt.Sprintf("https://localhost:%d/datagrams", port))
			defer closeFn()
			go str.Read([]byte{0})

			Expect(str.SendDatagram([]byte("foo"))).To(Succeed())
			Eventually(datagramChan).Should(Receive(Equal([]byte("foo"))))
			// signal that we're done sending

			var resetErr error
			Eventually(errChan).Should(Receive(&resetErr))
			Expect(resetErr).To(Equal(&quic.StreamError{ErrorCode: 42, Remote: false}))

			// make sure we can't send anymore
			Expect(str.SendDatagram([]byte("foo"))).To(Equal(&quic.StreamError{ErrorCode: 42, Remote: true}))
		})
	})

	Context("0-RTT", func() {
		runCountingProxy := func(serverPort int, rtt time.Duration) (*quicproxy.QuicProxy, *atomic.Uint32) {
			var num0RTTPackets atomic.Uint32
			proxy, err := quicproxy.NewQuicProxy("localhost:0", &quicproxy.Opts{
				RemoteAddr: fmt.Sprintf("localhost:%d", serverPort),
				DelayPacket: func(_ quicproxy.Direction, data []byte) time.Duration {
					if contains0RTTPacket(data) {
						num0RTTPackets.Add(1)
					}
					return rtt / 2
				},
			})
			Expect(err).ToNot(HaveOccurred())
			return proxy, &num0RTTPackets
		}

		It("sends 0-RTT GET requests", func() {
			proxy, num0RTTPackets := runCountingProxy(port, scaleDuration(50*time.Millisecond))
			defer proxy.Close()

			tlsConf := getTLSClientConfigWithoutServerName()
			puts := make(chan string, 10)
			tlsConf.ClientSessionCache = newClientSessionCache(tls.NewLRUClientSessionCache(10), nil, puts)
			rt := &http3.RoundTripper{
				TLSClientConfig: tlsConf,
				QUICConfig: getQuicConfig(&quic.Config{
					MaxIdleTimeout: 10 * time.Second,
				}),
				DisableCompression: true,
			}
			defer rt.Close()

			mux.HandleFunc("/0rtt", func(w http.ResponseWriter, r *http.Request) {
				w.Write([]byte(strconv.FormatBool(!r.TLS.HandshakeComplete)))
			})
			req, err := http.NewRequest(http3.MethodGet0RTT, fmt.Sprintf("https://localhost:%d/0rtt", proxy.LocalPort()), nil)
			Expect(err).ToNot(HaveOccurred())
			rsp, err := rt.RoundTrip(req)
			Expect(err).ToNot(HaveOccurred())
			Expect(rsp.StatusCode).To(BeEquivalentTo(200))
			data, err := io.ReadAll(rsp.Body)
			Expect(err).ToNot(HaveOccurred())
			Expect(string(data)).To(Equal("false"))
			Expect(num0RTTPackets.Load()).To(BeZero())
			Eventually(puts).Should(Receive())

			rt2 := &http3.RoundTripper{
				TLSClientConfig:    rt.TLSClientConfig,
				QUICConfig:         rt.QUICConfig,
				DisableCompression: true,
			}
			defer rt2.Close()
			rsp, err = rt2.RoundTrip(req)
			Expect(err).ToNot(HaveOccurred())
			Expect(rsp.StatusCode).To(BeEquivalentTo(200))
			data, err = io.ReadAll(rsp.Body)
			Expect(err).ToNot(HaveOccurred())
			Expect(string(data)).To(Equal("true"))
			Expect(num0RTTPackets.Load()).To(BeNumerically(">", 0))
		})
	})
})
