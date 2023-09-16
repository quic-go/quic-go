package self_test

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"

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
			QuicConfig: getQuicConfig(nil),
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
			TLSClientConfig:    getTLSClientConfigWithoutServerName(),
			DisableCompression: true,
			QuicConfig:         getQuicConfig(&quic.Config{MaxIdleTimeout: 10 * time.Second}),
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
			w.Write([]byte("foobar"))
		})

		resp, err := client.Get(fmt.Sprintf("https://localhost:%d/small", port))
		Expect(err).ToNot(HaveOccurred())
		Expect(resp.StatusCode).To(Equal(200))
		Expect(resp.Header.Get("Content-Length")).To(Equal(strconv.Itoa(len("foobar"))))
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

	It("cancels requests", func() {
		handlerCalled := make(chan struct{})
		mux.HandleFunc("/cancel", func(w http.ResponseWriter, r *http.Request) {
			defer GinkgoRecover()
			defer close(handlerCalled)
			for {
				if _, err := w.Write([]byte("foobar")); err != nil {
					Expect(r.Context().Done()).To(BeClosed())
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
		mux.HandleFunc("/httpstreamer", func(w http.ResponseWriter, r *http.Request) {
			defer GinkgoRecover()
			w.WriteHeader(200)
			w.(http.Flusher).Flush()

			str := r.Body.(http3.HTTPStreamer).HTTPStream()
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
		rsp, err := client.Transport.(*http3.RoundTripper).RoundTripOpt(req, http3.RoundTripOpt{DontCloseRequestStream: true})
		Expect(err).ToNot(HaveOccurred())
		Expect(rsp.StatusCode).To(Equal(200))

		str := rsp.Body.(http3.HTTPStreamer).HTTPStream()
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

	It("serves other QUIC connections", func() {
		tlsConf := getTLSConfig()
		tlsConf.NextProtos = []string{http3.NextProtoH3}
		ln, err := quic.ListenAddr("localhost:0", tlsConf, nil)
		Expect(err).ToNot(HaveOccurred())
		defer ln.Close()
		done := make(chan struct{})
		go func() {
			defer GinkgoRecover()
			defer close(done)
			conn, err := ln.Accept(context.Background())
			Expect(err).ToNot(HaveOccurred())
			Expect(server.ServeQUICConn(conn)).To(Succeed())
		}()

		resp, err := client.Get(fmt.Sprintf("https://localhost:%d/hello", ln.Addr().(*net.UDPAddr).Port))
		Expect(err).ToNot(HaveOccurred())
		Expect(resp.StatusCode).To(Equal(http.StatusOK))
		client.Transport.(io.Closer).Close()
		Eventually(done).Should(BeClosed())
	})

	if go120 {
		It("supports read deadlines", func() {
			mux.HandleFunc("/read-deadline", func(w http.ResponseWriter, r *http.Request) {
				defer GinkgoRecover()
				err := setReadDeadline(w, time.Now().Add(deadlineDelay))
				Expect(err).ToNot(HaveOccurred())

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
				err := setWriteDeadline(w, time.Now().Add(deadlineDelay))
				Expect(err).ToNot(HaveOccurred())

				_, err = io.Copy(w, neverEnding('a'))
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
	}
})
