package http3

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/golang/mock/gomock"
	quic "github.com/lucas-clemente/quic-go"
	mockquic "github.com/lucas-clemente/quic-go/internal/mocks/quic"
	"github.com/lucas-clemente/quic-go/internal/utils"
	"github.com/marten-seemann/qpack"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Client", func() {
	var (
		client       *client
		req          *http.Request
		origDialAddr = dialAddr
	)

	BeforeEach(func() {
		origDialAddr = dialAddr
		hostname := "quic.clemente.io:1337"
		client = newClient(hostname, nil, &roundTripperOpts{MaxHeaderBytes: 1337}, nil, nil)
		Expect(client.hostname).To(Equal(hostname))

		var err error
		req, err = http.NewRequest("GET", "https://localhost:1337", nil)
		Expect(err).ToNot(HaveOccurred())
	})

	AfterEach(func() {
		dialAddr = origDialAddr
	})

	It("uses the default QUIC and TLS config if none is give", func() {
		client = newClient("localhost:1337", nil, &roundTripperOpts{}, nil, nil)
		var dialAddrCalled bool
		dialAddr = func(_ string, tlsConf *tls.Config, quicConf *quic.Config) (quic.Session, error) {
			Expect(quicConf).To(Equal(defaultQuicConfig))
			Expect(tlsConf.NextProtos).To(Equal([]string{nextProtoH3}))
			dialAddrCalled = true
			return nil, errors.New("test done")
		}
		client.RoundTrip(req)
		Expect(dialAddrCalled).To(BeTrue())
	})

	It("adds the port to the hostname, if none is given", func() {
		client = newClient("quic.clemente.io", nil, &roundTripperOpts{}, nil, nil)
		var dialAddrCalled bool
		dialAddr = func(hostname string, _ *tls.Config, _ *quic.Config) (quic.Session, error) {
			Expect(hostname).To(Equal("quic.clemente.io:443"))
			dialAddrCalled = true
			return nil, errors.New("test done")
		}
		req, err := http.NewRequest("GET", "https://quic.clemente.io:443", nil)
		Expect(err).ToNot(HaveOccurred())
		client.RoundTrip(req)
		Expect(dialAddrCalled).To(BeTrue())
	})

	It("uses the TLS config and QUIC config", func() {
		tlsConf := &tls.Config{
			ServerName: "foo.bar",
			NextProtos: []string{"proto foo", "proto bar"},
		}
		quicConf := &quic.Config{IdleTimeout: time.Nanosecond}
		client = newClient("localhost:1337", tlsConf, &roundTripperOpts{}, quicConf, nil)
		var dialAddrCalled bool
		dialAddr = func(
			hostname string,
			tlsConfP *tls.Config,
			quicConfP *quic.Config,
		) (quic.Session, error) {
			Expect(hostname).To(Equal("localhost:1337"))
			Expect(tlsConfP.ServerName).To(Equal(tlsConf.ServerName))
			Expect(tlsConfP.NextProtos).To(Equal([]string{nextProtoH3}))
			Expect(quicConfP.IdleTimeout).To(Equal(quicConf.IdleTimeout))
			dialAddrCalled = true
			return nil, errors.New("test done")
		}
		client.RoundTrip(req)
		Expect(dialAddrCalled).To(BeTrue())
		// make sure the original tls.Config was not modified
		Expect(tlsConf.NextProtos).To(Equal([]string{"proto foo", "proto bar"}))
	})

	It("uses the custom dialer, if provided", func() {
		testErr := errors.New("test done")
		tlsConf := &tls.Config{ServerName: "foo.bar"}
		quicConf := &quic.Config{IdleTimeout: 1337 * time.Second}
		var dialerCalled bool
		dialer := func(network, address string, tlsConfP *tls.Config, quicConfP *quic.Config) (quic.Session, error) {
			Expect(network).To(Equal("udp"))
			Expect(address).To(Equal("localhost:1337"))
			Expect(tlsConfP.ServerName).To(Equal("foo.bar"))
			Expect(quicConfP.IdleTimeout).To(Equal(quicConf.IdleTimeout))
			dialerCalled = true
			return nil, testErr
		}
		client = newClient("localhost:1337", tlsConf, &roundTripperOpts{}, quicConf, dialer)
		_, err := client.RoundTrip(req)
		Expect(err).To(MatchError(testErr))
		Expect(dialerCalled).To(BeTrue())
	})

	It("errors when dialing fails", func() {
		testErr := errors.New("handshake error")
		client = newClient("localhost:1337", nil, &roundTripperOpts{}, nil, nil)
		dialAddr = func(hostname string, _ *tls.Config, _ *quic.Config) (quic.Session, error) {
			return nil, testErr
		}
		_, err := client.RoundTrip(req)
		Expect(err).To(MatchError(testErr))
	})

	It("errors if it can't open a stream", func() {
		testErr := errors.New("stream open error")
		client = newClient("localhost:1337", nil, &roundTripperOpts{}, nil, nil)
		session := mockquic.NewMockSession(mockCtrl)
		session.EXPECT().OpenUniStream().Return(nil, testErr).MaxTimes(1)
		session.EXPECT().OpenStreamSync(context.Background()).Return(nil, testErr).MaxTimes(1)
		session.EXPECT().CloseWithError(gomock.Any(), gomock.Any()).MaxTimes(1)
		dialAddr = func(hostname string, _ *tls.Config, _ *quic.Config) (quic.Session, error) {
			return session, nil
		}
		defer GinkgoRecover()
		_, err := client.RoundTrip(req)
		Expect(err).To(MatchError(testErr))
	})

	Context("Doing requests", func() {
		var (
			request *http.Request
			str     *mockquic.MockStream
			sess    *mockquic.MockSession
		)

		decodeHeader := func(str io.Reader) map[string]string {
			fields := make(map[string]string)
			decoder := qpack.NewDecoder(nil)

			frame, err := parseNextFrame(str)
			ExpectWithOffset(1, err).ToNot(HaveOccurred())
			ExpectWithOffset(1, frame).To(BeAssignableToTypeOf(&headersFrame{}))
			headersFrame := frame.(*headersFrame)
			data := make([]byte, headersFrame.Length)
			_, err = io.ReadFull(str, data)
			ExpectWithOffset(1, err).ToNot(HaveOccurred())
			hfs, err := decoder.DecodeFull(data)
			ExpectWithOffset(1, err).ToNot(HaveOccurred())
			for _, p := range hfs {
				fields[p.Name] = p.Value
			}
			return fields
		}

		BeforeEach(func() {
			controlStr := mockquic.NewMockStream(mockCtrl)
			controlStr.EXPECT().Write([]byte{0x0}).Return(1, nil).MaxTimes(1)
			controlStr.EXPECT().Write(gomock.Any()).MaxTimes(1) // SETTINGS frame
			str = mockquic.NewMockStream(mockCtrl)
			sess = mockquic.NewMockSession(mockCtrl)
			sess.EXPECT().OpenUniStream().Return(controlStr, nil).MaxTimes(1)
			dialAddr = func(hostname string, _ *tls.Config, _ *quic.Config) (quic.Session, error) {
				return sess, nil
			}
			var err error
			request, err = http.NewRequest("GET", "https://quic.clemente.io:1337/file1.dat", nil)
			Expect(err).ToNot(HaveOccurred())
		})

		It("returns a response", func() {
			rspBuf := &bytes.Buffer{}
			rw := newResponseWriter(rspBuf, utils.DefaultLogger)
			rw.WriteHeader(418)

			sess.EXPECT().OpenStreamSync(context.Background()).Return(str, nil)
			str.EXPECT().Write(gomock.Any()).AnyTimes()
			str.EXPECT().Close()
			str.EXPECT().Read(gomock.Any()).DoAndReturn(func(p []byte) (int, error) {
				return rspBuf.Read(p)
			}).AnyTimes()
			rsp, err := client.RoundTrip(request)
			Expect(err).ToNot(HaveOccurred())
			Expect(rsp.Proto).To(Equal("HTTP/3"))
			Expect(rsp.ProtoMajor).To(Equal(3))
			Expect(rsp.StatusCode).To(Equal(418))
		})

		Context("validating the address", func() {
			It("refuses to do requests for the wrong host", func() {
				req, err := http.NewRequest("https", "https://quic.clemente.io:1336/foobar.html", nil)
				Expect(err).ToNot(HaveOccurred())
				_, err = client.RoundTrip(req)
				Expect(err).To(MatchError("http3 client BUG: RoundTrip called for the wrong client (expected quic.clemente.io:1337, got quic.clemente.io:1336)"))
			})

			It("refuses to do plain HTTP requests", func() {
				req, err := http.NewRequest("https", "http://quic.clemente.io:1337/foobar.html", nil)
				Expect(err).ToNot(HaveOccurred())
				_, err = client.RoundTrip(req)
				Expect(err).To(MatchError("http3: unsupported scheme"))
			})
		})

		Context("requests containing a Body", func() {
			var strBuf *bytes.Buffer

			BeforeEach(func() {
				strBuf = &bytes.Buffer{}
				sess.EXPECT().OpenStreamSync(context.Background()).Return(str, nil)
				body := &mockBody{}
				body.SetData([]byte("request body"))
				var err error
				request, err = http.NewRequest("POST", "https://quic.clemente.io:1337/upload", body)
				Expect(err).ToNot(HaveOccurred())
				str.EXPECT().Write(gomock.Any()).DoAndReturn(func(p []byte) (int, error) {
					return strBuf.Write(p)
				}).AnyTimes()
			})

			It("sends a request", func() {
				done := make(chan struct{})
				gomock.InOrder(
					str.EXPECT().Close().Do(func() { close(done) }),
					str.EXPECT().CancelWrite(gomock.Any()).MaxTimes(1), // when reading the response errors
				)
				// the response body is sent asynchronously, while already reading the response
				str.EXPECT().Read(gomock.Any()).DoAndReturn(func([]byte) (int, error) {
					<-done
					return 0, errors.New("test done")
				})
				_, err := client.RoundTrip(request)
				Expect(err).To(MatchError("test done"))
				hfs := decodeHeader(strBuf)
				Expect(hfs).To(HaveKeyWithValue(":method", "POST"))
				Expect(hfs).To(HaveKeyWithValue(":path", "/upload"))
			})

			It("returns the error that occurred when reading the body", func() {
				request.Body.(*mockBody).readErr = errors.New("testErr")
				done := make(chan struct{})
				gomock.InOrder(
					str.EXPECT().CancelWrite(quic.ErrorCode(errorRequestCanceled)).Do(func(quic.ErrorCode) {
						close(done)
					}),
					str.EXPECT().CancelWrite(gomock.Any()),
				)

				// the response body is sent asynchronously, while already reading the response
				str.EXPECT().Read(gomock.Any()).DoAndReturn(func([]byte) (int, error) {
					<-done
					return 0, errors.New("test done")
				})
				_, err := client.RoundTrip(request)
				Expect(err).To(MatchError("test done"))
			})

			It("closes the connection when the first frame is not a HEADERS frame", func() {
				buf := &bytes.Buffer{}
				(&dataFrame{Length: 0x42}).Write(buf)
				sess.EXPECT().CloseWithError(quic.ErrorCode(errorFrameUnexpected), gomock.Any())
				closed := make(chan struct{})
				str.EXPECT().Close().Do(func() { close(closed) })
				str.EXPECT().Read(gomock.Any()).DoAndReturn(func(b []byte) (int, error) {
					return buf.Read(b)
				}).AnyTimes()
				_, err := client.RoundTrip(request)
				Expect(err).To(MatchError("expected first frame to be a HEADERS frame"))
				Eventually(closed).Should(BeClosed())
			})

			It("cancels the stream when the HEADERS frame is too large", func() {
				buf := &bytes.Buffer{}
				(&headersFrame{Length: 1338}).Write(buf)
				str.EXPECT().CancelWrite(quic.ErrorCode(errorFrameError))
				closed := make(chan struct{})
				str.EXPECT().Close().Do(func() { close(closed) })
				str.EXPECT().Read(gomock.Any()).DoAndReturn(func(b []byte) (int, error) {
					return buf.Read(b)
				}).AnyTimes()
				_, err := client.RoundTrip(request)
				Expect(err).To(MatchError("HEADERS frame too large: 1338 bytes (max: 1337)"))
				Eventually(closed).Should(BeClosed())
			})
		})

		Context("request cancellations", func() {
			It("cancels a request while the request is still in flight", func() {
				ctx, cancel := context.WithCancel(context.Background())
				req := request.WithContext(ctx)
				sess.EXPECT().OpenStreamSync(context.Background()).Return(str, nil)
				buf := &bytes.Buffer{}
				str.EXPECT().Close().MaxTimes(1)

				str.EXPECT().Write(gomock.Any()).DoAndReturn(func(p []byte) (int, error) {
					return buf.Write(p)
				})

				done := make(chan struct{})
				canceled := make(chan struct{})
				gomock.InOrder(
					str.EXPECT().CancelWrite(quic.ErrorCode(errorRequestCanceled)).Do(func(quic.ErrorCode) { close(canceled) }),
					str.EXPECT().CancelRead(quic.ErrorCode(errorRequestCanceled)).Do(func(quic.ErrorCode) { close(done) }),
				)
				str.EXPECT().CancelWrite(gomock.Any()).MaxTimes(1)
				str.EXPECT().Read(gomock.Any()).DoAndReturn(func([]byte) (int, error) {
					cancel()
					<-canceled
					return 0, errors.New("test done")
				})
				_, err := client.RoundTrip(req)
				Expect(err).To(MatchError("test done"))
				Eventually(done).Should(BeClosed())
			})

			It("cancels a request after the response arrived", func() {
				rspBuf := &bytes.Buffer{}
				rw := newResponseWriter(rspBuf, utils.DefaultLogger)
				rw.WriteHeader(418)

				ctx, cancel := context.WithCancel(context.Background())
				req := request.WithContext(ctx)
				sess.EXPECT().OpenStreamSync(context.Background()).Return(str, nil)
				buf := &bytes.Buffer{}
				str.EXPECT().Close().MaxTimes(1)

				done := make(chan struct{})
				str.EXPECT().Write(gomock.Any()).DoAndReturn(func(p []byte) (int, error) {
					return buf.Write(p)
				})
				str.EXPECT().Read(gomock.Any()).DoAndReturn(func(b []byte) (int, error) {
					return rspBuf.Read(b)
				}).AnyTimes()
				str.EXPECT().CancelWrite(quic.ErrorCode(errorRequestCanceled))
				str.EXPECT().CancelRead(quic.ErrorCode(errorRequestCanceled)).Do(func(quic.ErrorCode) { close(done) })
				_, err := client.RoundTrip(req)
				Expect(err).ToNot(HaveOccurred())
				cancel()
				Eventually(done).Should(BeClosed())
			})
		})

		Context("gzip compression", func() {
			var gzippedData []byte // a gzipped foobar
			var response *http.Response

			BeforeEach(func() {
				var b bytes.Buffer
				w := gzip.NewWriter(&b)
				w.Write([]byte("foobar"))
				w.Close()
				gzippedData = b.Bytes()
				response = &http.Response{
					StatusCode: 200,
					Header:     http.Header{"Content-Length": []string{"1000"}},
				}
				_ = gzippedData
				_ = response
			})

			It("adds the gzip header to requests", func() {
				sess.EXPECT().OpenStreamSync(context.Background()).Return(str, nil)
				buf := &bytes.Buffer{}
				str.EXPECT().Write(gomock.Any()).DoAndReturn(func(p []byte) (int, error) {
					return buf.Write(p)
				})
				gomock.InOrder(
					str.EXPECT().Close(),
					str.EXPECT().CancelWrite(gomock.Any()).MaxTimes(1), // when the Read errors
				)
				str.EXPECT().Read(gomock.Any()).Return(0, errors.New("test done"))
				_, err := client.RoundTrip(request)
				Expect(err).To(MatchError("test done"))
				hfs := decodeHeader(buf)
				Expect(hfs).To(HaveKeyWithValue("accept-encoding", "gzip"))
			})

			It("doesn't add gzip if the header disable it", func() {
				client = newClient("quic.clemente.io:1337", nil, &roundTripperOpts{DisableCompression: true}, nil, nil)
				sess.EXPECT().OpenStreamSync(context.Background()).Return(str, nil)
				buf := &bytes.Buffer{}
				str.EXPECT().Write(gomock.Any()).DoAndReturn(func(p []byte) (int, error) {
					return buf.Write(p)
				})
				gomock.InOrder(
					str.EXPECT().Close(),
					str.EXPECT().CancelWrite(gomock.Any()).MaxTimes(1), // when the Read errors
				)
				str.EXPECT().Read(gomock.Any()).Return(0, errors.New("test done"))
				_, err := client.RoundTrip(request)
				Expect(err).To(MatchError("test done"))
				hfs := decodeHeader(buf)
				Expect(hfs).ToNot(HaveKey("accept-encoding"))
			})

			It("decompresses the response", func() {
				sess.EXPECT().OpenStreamSync(context.Background()).Return(str, nil)
				buf := &bytes.Buffer{}
				rw := newResponseWriter(buf, utils.DefaultLogger)
				rw.Header().Set("Content-Encoding", "gzip")
				gz := gzip.NewWriter(rw)
				gz.Write([]byte("gzipped response"))
				gz.Close()
				str.EXPECT().Write(gomock.Any()).AnyTimes()
				str.EXPECT().Read(gomock.Any()).DoAndReturn(func(p []byte) (int, error) {
					return buf.Read(p)
				}).AnyTimes()
				str.EXPECT().Close()

				rsp, err := client.RoundTrip(request)
				Expect(err).ToNot(HaveOccurred())
				data, err := ioutil.ReadAll(rsp.Body)
				Expect(err).ToNot(HaveOccurred())
				Expect(rsp.ContentLength).To(BeEquivalentTo(-1))
				Expect(string(data)).To(Equal("gzipped response"))
				Expect(rsp.Header.Get("Content-Encoding")).To(BeEmpty())
				Expect(rsp.Uncompressed).To(BeTrue())
			})

			It("only decompresses the response if the response contains the right content-encoding header", func() {
				sess.EXPECT().OpenStreamSync(context.Background()).Return(str, nil)
				buf := &bytes.Buffer{}
				rw := newResponseWriter(buf, utils.DefaultLogger)
				rw.Write([]byte("not gzipped"))
				str.EXPECT().Write(gomock.Any()).AnyTimes()
				str.EXPECT().Read(gomock.Any()).DoAndReturn(func(p []byte) (int, error) {
					return buf.Read(p)
				}).AnyTimes()
				str.EXPECT().Close()

				rsp, err := client.RoundTrip(request)
				Expect(err).ToNot(HaveOccurred())
				data, err := ioutil.ReadAll(rsp.Body)
				Expect(err).ToNot(HaveOccurred())
				Expect(rsp.ContentLength).ToNot(BeEquivalentTo(-1))
				Expect(string(data)).To(Equal("not gzipped"))
				Expect(rsp.Header.Get("Content-Encoding")).To(BeEmpty())
			})
		})
	})
})
