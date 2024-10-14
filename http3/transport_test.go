package http3

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/quic-go/quic-go"
	mockquic "github.com/quic-go/quic-go/internal/mocks/quic"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/qerr"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"go.uber.org/mock/gomock"
)

type mockBody struct {
	reader   bytes.Reader
	readErr  error
	closeErr error
	closed   bool
}

// make sure the mockBody can be used as a http.Request.Body
var _ io.ReadCloser = &mockBody{}

func (m *mockBody) Read(p []byte) (int, error) {
	if m.readErr != nil {
		return 0, m.readErr
	}
	return m.reader.Read(p)
}

func (m *mockBody) SetData(data []byte) {
	m.reader = *bytes.NewReader(data)
}

func (m *mockBody) Close() error {
	m.closed = true
	return m.closeErr
}

var _ = Describe("Transport", func() {
	var req *http.Request

	BeforeEach(func() {
		var err error
		req, err = http.NewRequest("GET", "https://www.example.org/file1.html", nil)
		Expect(err).ToNot(HaveOccurred())
	})

	It("rejects quic.Configs that allow multiple QUIC versions", func() {
		qconf := &quic.Config{
			Versions: []quic.Version{protocol.Version2, protocol.Version1},
		}
		tr := &Transport{QUICConfig: qconf}
		_, err := tr.RoundTrip(req)
		Expect(err).To(MatchError("can only use a single QUIC version for dialing a HTTP/3 connection"))
	})

	It("uses the default QUIC and TLS config if none is give", func() {
		var dialAddrCalled bool
		tr := &Transport{
			Dial: func(_ context.Context, _ string, tlsConf *tls.Config, quicConf *quic.Config) (quic.EarlyConnection, error) {
				defer GinkgoRecover()
				Expect(quicConf.MaxIncomingStreams).To(Equal(defaultQuicConfig.MaxIncomingStreams))
				Expect(tlsConf.NextProtos).To(Equal([]string{NextProtoH3}))
				Expect(quicConf.Versions).To(Equal([]protocol.Version{protocol.Version1}))
				dialAddrCalled = true
				return nil, errors.New("test done")
			},
		}
		_, err := tr.RoundTripOpt(req, RoundTripOpt{})
		Expect(err).To(MatchError("test done"))
		Expect(dialAddrCalled).To(BeTrue())
	})

	It("adds the port to the hostname, if none is given", func() {
		var dialAddrCalled bool
		tr := &Transport{
			Dial: func(_ context.Context, hostname string, _ *tls.Config, _ *quic.Config) (quic.EarlyConnection, error) {
				defer GinkgoRecover()
				Expect(hostname).To(Equal("quic.clemente.io:443"))
				dialAddrCalled = true
				return nil, errors.New("test done")
			},
		}
		req, err := http.NewRequest("GET", "https://quic.clemente.io:443", nil)
		Expect(err).ToNot(HaveOccurred())
		_, err = tr.RoundTripOpt(req, RoundTripOpt{})
		Expect(err).To(MatchError("test done"))
		Expect(dialAddrCalled).To(BeTrue())
	})

	It("sets the ServerName in the tls.Config, if not set", func() {
		const host = "foo.bar"
		var dialCalled bool
		tr := &Transport{
			Dial: func(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (quic.EarlyConnection, error) {
				defer GinkgoRecover()
				Expect(tlsCfg.ServerName).To(Equal(host))
				dialCalled = true
				return nil, errors.New("test done")
			},
		}
		req, err := http.NewRequest("GET", "https://foo.bar", nil)
		Expect(err).ToNot(HaveOccurred())
		_, err = tr.RoundTripOpt(req, RoundTripOpt{})
		Expect(err).To(MatchError("test done"))
		Expect(dialCalled).To(BeTrue())
	})

	It("uses the TLS config and QUIC config", func() {
		tlsConf := &tls.Config{
			ServerName: "foo.bar",
			NextProtos: []string{"proto foo", "proto bar"},
		}
		quicConf := &quic.Config{MaxIdleTimeout: 3 * time.Nanosecond}
		var dialAddrCalled bool
		tr := &Transport{
			Dial: func(_ context.Context, host string, tlsConfP *tls.Config, quicConfP *quic.Config) (quic.EarlyConnection, error) {
				defer GinkgoRecover()
				Expect(host).To(Equal("www.example.org:443"))
				Expect(tlsConfP.ServerName).To(Equal(tlsConf.ServerName))
				Expect(tlsConfP.NextProtos).To(Equal([]string{NextProtoH3}))
				Expect(quicConfP.MaxIdleTimeout).To(Equal(quicConf.MaxIdleTimeout))
				dialAddrCalled = true
				return nil, errors.New("test done")
			},
			QUICConfig:      quicConf,
			TLSClientConfig: tlsConf,
		}
		_, err := tr.RoundTripOpt(req, RoundTripOpt{})
		Expect(err).To(MatchError("test done"))
		Expect(dialAddrCalled).To(BeTrue())
		// make sure the original tls.Config was not modified
		Expect(tlsConf.NextProtos).To(Equal([]string{"proto foo", "proto bar"}))
	})

	It("uses the custom dialer, if provided", func() {
		testErr := errors.New("test done")
		tlsConf := &tls.Config{ServerName: "foo.bar"}
		quicConf := &quic.Config{MaxIdleTimeout: 1337 * time.Second}
		// nolint:staticcheck // This is a test.
		ctx := context.WithValue(context.Background(), "foo", "bar")
		var dialerCalled bool
		tr := &Transport{
			Dial: func(ctxP context.Context, address string, tlsConfP *tls.Config, quicConfP *quic.Config) (quic.EarlyConnection, error) {
				defer GinkgoRecover()
				Expect(ctx.Value("foo").(string)).To(Equal("bar"))
				Expect(address).To(Equal("www.example.org:443"))
				Expect(tlsConfP.ServerName).To(Equal("foo.bar"))
				Expect(quicConfP.MaxIdleTimeout).To(Equal(quicConf.MaxIdleTimeout))
				dialerCalled = true
				return nil, testErr
			},
			TLSClientConfig: tlsConf,
			QUICConfig:      quicConf,
		}
		_, err := tr.RoundTripOpt(req.WithContext(ctx), RoundTripOpt{})
		Expect(err).To(MatchError(testErr))
		Expect(dialerCalled).To(BeTrue())
	})

	It("enables HTTP/3 Datagrams", func() {
		testErr := errors.New("handshake error")
		tr := &Transport{
			EnableDatagrams: true,
			Dial: func(_ context.Context, _ string, _ *tls.Config, quicConf *quic.Config) (quic.EarlyConnection, error) {
				defer GinkgoRecover()
				Expect(quicConf.EnableDatagrams).To(BeTrue())
				return nil, testErr
			},
		}
		_, err := tr.RoundTripOpt(req, RoundTripOpt{})
		Expect(err).To(MatchError(testErr))
	})

	It("requires quic.Config.EnableDatagrams if HTTP/3 datagrams are enabled", func() {
		tr := &Transport{
			QUICConfig:      &quic.Config{EnableDatagrams: false},
			EnableDatagrams: true,
			Dial: func(_ context.Context, _ string, _ *tls.Config, config *quic.Config) (quic.EarlyConnection, error) {
				return nil, errors.New("handshake error")
			},
		}
		_, err := tr.RoundTrip(req)
		Expect(err).To(MatchError("HTTP Datagrams enabled, but QUIC Datagrams disabled"))
	})

	It("creates new clients", func() {
		testErr := errors.New("test err")
		req1, err := http.NewRequest("GET", "https://quic-go.net/foobar.html", nil)
		Expect(err).ToNot(HaveOccurred())
		req2, err := http.NewRequest("GET", "https://example.com/foobar.html", nil)
		Expect(err).ToNot(HaveOccurred())
		var hostsDialed []string
		tr := &Transport{
			Dial: func(_ context.Context, host string, _ *tls.Config, quicConf *quic.Config) (quic.EarlyConnection, error) {
				hostsDialed = append(hostsDialed, host)
				return nil, testErr
			},
		}
		_, err = tr.RoundTrip(req1)
		Expect(err).To(MatchError(testErr))
		_, err = tr.RoundTrip(req2)
		Expect(err).To(MatchError(testErr))
		Expect(hostsDialed).To(Equal([]string{"quic-go.net:443", "example.com:443"}))
	})

	Context("reusing clients", func() {
		var (
			tr         *Transport
			req1, req2 *http.Request
			clientChan chan *MockSingleRoundTripper
		)

		BeforeEach(func() {
			clientChan = make(chan *MockSingleRoundTripper, 16)
			tr = &Transport{
				newClient: func(quic.EarlyConnection) singleRoundTripper {
					select {
					case c := <-clientChan:
						return c
					default:
						Fail("no client")
						return nil
					}
				},
			}
			var err error
			req1, err = http.NewRequest("GET", "https://quic-go.net/file1.html", nil)
			Expect(err).ToNot(HaveOccurred())
			req2, err = http.NewRequest("GET", "https://quic-go.net/file2.html", nil)
			Expect(err).ToNot(HaveOccurred())
			Expect(req1.URL).ToNot(Equal(req2.URL))
		})

		It("reuses existing clients", func() {
			cl := NewMockSingleRoundTripper(mockCtrl)
			clientChan <- cl
			conn := mockquic.NewMockEarlyConnection(mockCtrl)
			handshakeChan := make(chan struct{})
			close(handshakeChan)
			conn.EXPECT().HandshakeComplete().Return(handshakeChan).MaxTimes(2)

			cl.EXPECT().RoundTrip(req1).Return(&http.Response{Request: req1}, nil)
			cl.EXPECT().RoundTrip(req2).Return(&http.Response{Request: req2}, nil)
			var count int
			tr.Dial = func(context.Context, string, *tls.Config, *quic.Config) (quic.EarlyConnection, error) {
				count++
				return conn, nil
			}
			rsp, err := tr.RoundTrip(req1)
			Expect(err).ToNot(HaveOccurred())
			Expect(rsp.Request).To(Equal(req1))
			rsp, err = tr.RoundTrip(req2)
			Expect(err).ToNot(HaveOccurred())
			Expect(rsp.Request).To(Equal(req2))
			Expect(count).To(Equal(1))
		})

		It("redials a connection if dialing failed", func() {
			cl1 := NewMockSingleRoundTripper(mockCtrl)
			clientChan <- cl1

			req1, err := http.NewRequest("GET", "https://quic-go.net/foo.html", nil)
			Expect(err).ToNot(HaveOccurred())
			req2, err := http.NewRequest("GET", "https://quic-go.net/bar.html", nil)
			Expect(err).ToNot(HaveOccurred())

			testErr := errors.New("handshake error")
			conn := mockquic.NewMockEarlyConnection(mockCtrl)
			var count int
			tr.Dial = func(context.Context, string, *tls.Config, *quic.Config) (quic.EarlyConnection, error) {
				count++
				if count == 1 {
					return nil, testErr
				}
				return conn, nil
			}
			handshakeChan := make(chan struct{})
			close(handshakeChan)
			conn.EXPECT().HandshakeComplete().Return(handshakeChan).MaxTimes(2)
			cl1.EXPECT().RoundTrip(req2).Return(&http.Response{Request: req2}, nil)
			_, err = tr.RoundTrip(req1)
			Expect(err).To(MatchError(testErr))
			rsp, err := tr.RoundTrip(req2)
			Expect(err).ToNot(HaveOccurred())
			Expect(rsp.Request).To(Equal(req2))
			Expect(count).To(Equal(2))
		})

		It("immediately removes a clients when a request errored", func() {
			cl1 := NewMockSingleRoundTripper(mockCtrl)
			clientChan <- cl1
			cl2 := NewMockSingleRoundTripper(mockCtrl)
			clientChan <- cl2

			req1, err := http.NewRequest("GET", "https://quic-go.net/foobar.html", nil)
			Expect(err).ToNot(HaveOccurred())
			req2, err := http.NewRequest("GET", "https://quic-go.net/bar.html", nil)
			Expect(err).ToNot(HaveOccurred())

			conn := mockquic.NewMockEarlyConnection(mockCtrl)
			var count int
			tr.Dial = func(context.Context, string, *tls.Config, *quic.Config) (quic.EarlyConnection, error) {
				count++
				return conn, nil
			}
			testErr := errors.New("test err")
			handshakeChan := make(chan struct{})
			close(handshakeChan)
			conn.EXPECT().HandshakeComplete().Return(handshakeChan).MaxTimes(2)
			cl1.EXPECT().RoundTrip(req1).Return(nil, testErr)
			cl2.EXPECT().RoundTrip(req2).Return(&http.Response{Request: req2}, nil)
			_, err = tr.RoundTrip(req1)
			Expect(err).To(MatchError(testErr))
			rsp, err := tr.RoundTrip(req2)
			Expect(err).ToNot(HaveOccurred())
			Expect(rsp.Request).To(Equal(req2))
			Expect(count).To(Equal(2))
		})

		It("does not remove a client when a request returns context canceled error", func() {
			cl1 := NewMockSingleRoundTripper(mockCtrl)
			clientChan <- cl1
			cl2 := NewMockSingleRoundTripper(mockCtrl)
			clientChan <- cl2

			req1, err := http.NewRequest("GET", "https://quic-go.net/foobar.html", nil)
			Expect(err).ToNot(HaveOccurred())
			req2, err := http.NewRequest("GET", "https://quic-go.net/bar.html", nil)
			Expect(err).ToNot(HaveOccurred())

			conn := mockquic.NewMockEarlyConnection(mockCtrl)
			var count int
			tr.Dial = func(context.Context, string, *tls.Config, *quic.Config) (quic.EarlyConnection, error) {
				count++
				return conn, nil
			}
			testErr := context.Canceled
			handshakeChan := make(chan struct{})
			close(handshakeChan)
			conn.EXPECT().HandshakeComplete().Return(handshakeChan).MaxTimes(2)
			cl1.EXPECT().RoundTrip(req1).Return(nil, testErr)
			cl1.EXPECT().RoundTrip(req2).Return(&http.Response{Request: req2}, nil)
			_, err = tr.RoundTrip(req1)
			Expect(err).To(MatchError(testErr))
			rsp, err := tr.RoundTrip(req2)
			Expect(err).ToNot(HaveOccurred())
			Expect(rsp.Request).To(Equal(req2))
			Expect(count).To(Equal(1))
		})

		It("recreates a client when a request times out", func() {
			var reqCount int
			cl1 := NewMockSingleRoundTripper(mockCtrl)
			cl1.EXPECT().RoundTrip(gomock.Any()).DoAndReturn(func(req *http.Request) (*http.Response, error) {
				reqCount++
				if reqCount == 1 { // the first request is successful...
					Expect(req.URL).To(Equal(req1.URL))
					return &http.Response{Request: req}, nil
				}
				// ... after that, the connection timed out in the background
				Expect(req.URL).To(Equal(req2.URL))
				return nil, &qerr.IdleTimeoutError{}
			}).Times(2)
			cl2 := NewMockSingleRoundTripper(mockCtrl)
			cl2.EXPECT().RoundTrip(gomock.Any()).DoAndReturn(func(req *http.Request) (*http.Response, error) {
				return &http.Response{Request: req}, nil
			})
			clientChan <- cl1
			clientChan <- cl2

			conn := mockquic.NewMockEarlyConnection(mockCtrl)
			handshakeChan := make(chan struct{})
			close(handshakeChan)
			conn.EXPECT().HandshakeComplete().Return(handshakeChan).MaxTimes(2)
			var count int
			tr.Dial = func(context.Context, string, *tls.Config, *quic.Config) (quic.EarlyConnection, error) {
				count++
				return conn, nil
			}
			rsp1, err := tr.RoundTrip(req1)
			Expect(err).ToNot(HaveOccurred())
			Expect(rsp1.Request.RemoteAddr).To(Equal(req1.RemoteAddr))
			rsp2, err := tr.RoundTrip(req2)
			Expect(err).ToNot(HaveOccurred())
			Expect(rsp2.Request.RemoteAddr).To(Equal(req2.RemoteAddr))
		})

		It("only issues a request once, even if a timeout error occurs", func() {
			var count int
			tr.Dial = func(context.Context, string, *tls.Config, *quic.Config) (quic.EarlyConnection, error) {
				count++
				return mockquic.NewMockEarlyConnection(mockCtrl), nil
			}
			tr.newClient = func(quic.EarlyConnection) singleRoundTripper {
				cl := NewMockSingleRoundTripper(mockCtrl)
				cl.EXPECT().RoundTrip(gomock.Any()).Return(nil, &qerr.IdleTimeoutError{})
				return cl
			}
			_, err := tr.RoundTrip(req1)
			Expect(err).To(MatchError(&qerr.IdleTimeoutError{}))
			Expect(count).To(Equal(1))
		})

		It("handles a burst of requests", func() {
			wait := make(chan struct{})
			reqs := make(chan struct{}, 2)

			cl := NewMockSingleRoundTripper(mockCtrl)
			cl.EXPECT().RoundTrip(gomock.Any()).DoAndReturn(func(req *http.Request) (*http.Response, error) {
				reqs <- struct{}{}
				<-wait
				return nil, &qerr.IdleTimeoutError{}
			}).Times(2)
			clientChan <- cl

			conn := mockquic.NewMockEarlyConnection(mockCtrl)
			conn.EXPECT().HandshakeComplete().Return(wait).AnyTimes()
			var count int
			tr.Dial = func(context.Context, string, *tls.Config, *quic.Config) (quic.EarlyConnection, error) {
				count++
				return conn, nil
			}

			done := make(chan struct{}, 2)
			go func() {
				defer GinkgoRecover()
				defer func() { done <- struct{}{} }()
				_, err := tr.RoundTrip(req1)
				Expect(err).To(MatchError(&qerr.IdleTimeoutError{}))
			}()
			// wait for the first requests to be issued
			Eventually(reqs).Should(Receive())
			go func() {
				defer GinkgoRecover()
				defer func() { done <- struct{}{} }()
				_, err := tr.RoundTrip(req2)
				Expect(err).To(MatchError(&qerr.IdleTimeoutError{}))
			}()
			Eventually(reqs).Should(Receive())
			close(wait) // now return the requests
			Eventually(done).Should(Receive())
			Eventually(done).Should(Receive())
			Expect(count).To(Equal(1))
		})

		It("doesn't create new clients if RoundTripOpt.OnlyCachedConn is set", func() {
			req, err := http.NewRequest("GET", "https://quic-go.net/foobar.html", nil)
			Expect(err).ToNot(HaveOccurred())
			_, err = tr.RoundTripOpt(req, RoundTripOpt{OnlyCachedConn: true})
			Expect(err).To(MatchError(ErrNoCachedConn))
		})
	})

	Context("validating request", func() {
		var tr Transport

		It("rejects plain HTTP requests", func() {
			req, err := http.NewRequest("GET", "http://www.example.org/", nil)
			req.Body = &mockBody{}
			Expect(err).ToNot(HaveOccurred())
			_, err = tr.RoundTrip(req)
			Expect(err).To(MatchError("http3: unsupported protocol scheme: http"))
			Expect(req.Body.(*mockBody).closed).To(BeTrue())
		})

		It("rejects requests without a URL", func() {
			req.URL = nil
			req.Body = &mockBody{}
			_, err := tr.RoundTrip(req)
			Expect(err).To(MatchError("http3: nil Request.URL"))
			Expect(req.Body.(*mockBody).closed).To(BeTrue())
		})

		It("rejects request without a URL Host", func() {
			req.URL.Host = ""
			req.Body = &mockBody{}
			_, err := tr.RoundTrip(req)
			Expect(err).To(MatchError("http3: no Host in request URL"))
			Expect(req.Body.(*mockBody).closed).To(BeTrue())
		})

		It("doesn't try to close the body if the request doesn't have one", func() {
			req.URL = nil
			Expect(req.Body).To(BeNil())
			_, err := tr.RoundTrip(req)
			Expect(err).To(MatchError("http3: nil Request.URL"))
		})

		It("rejects requests without a header", func() {
			req.Header = nil
			req.Body = &mockBody{}
			_, err := tr.RoundTrip(req)
			Expect(err).To(MatchError("http3: nil Request.Header"))
			Expect(req.Body.(*mockBody).closed).To(BeTrue())
		})

		It("rejects requests with invalid header name fields", func() {
			req.Header.Add("foobär", "value")
			_, err := tr.RoundTrip(req)
			Expect(err).To(MatchError("http3: invalid http header field name \"foobär\""))
		})

		It("rejects requests with invalid header name values", func() {
			req.Header.Add("foo", string([]byte{0x7}))
			_, err := tr.RoundTrip(req)
			Expect(err.Error()).To(ContainSubstring("http3: invalid http header field value"))
		})

		It("rejects requests with an invalid request method", func() {
			req.Method = "foobär"
			req.Body = &mockBody{}
			_, err := tr.RoundTrip(req)
			Expect(err).To(MatchError("http3: invalid method \"foobär\""))
			Expect(req.Body.(*mockBody).closed).To(BeTrue())
		})
	})

	Context("closing", func() {
		It("closes", func() {
			conn := mockquic.NewMockEarlyConnection(mockCtrl)
			tr := &Transport{
				Dial: func(context.Context, string, *tls.Config, *quic.Config) (quic.EarlyConnection, error) {
					return conn, nil
				},
				newClient: func(quic.EarlyConnection) singleRoundTripper {
					cl := NewMockSingleRoundTripper(mockCtrl)
					cl.EXPECT().RoundTrip(gomock.Any()).Return(&http.Response{}, nil)
					return cl
				},
			}
			req, err := http.NewRequest("GET", "https://quic-go.net/foobar.html", nil)
			Expect(err).ToNot(HaveOccurred())
			_, err = tr.RoundTrip(req)
			Expect(err).ToNot(HaveOccurred())
			conn.EXPECT().CloseWithError(quic.ApplicationErrorCode(0), "")
			Expect(tr.Close()).To(Succeed())
		})

		It("closes while dialing", func() {
			tr := &Transport{
				Dial: func(ctx context.Context, _ string, _ *tls.Config, _ *quic.Config) (quic.EarlyConnection, error) {
					defer GinkgoRecover()
					Eventually(ctx.Done()).Should(BeClosed())
					return nil, errors.New("cancelled")
				},
			}
			req, err := http.NewRequest("GET", "https://quic-go.net/foobar.html", nil)
			Expect(err).ToNot(HaveOccurred())

			errChan := make(chan error, 1)
			go func() {
				defer GinkgoRecover()
				_, err := tr.RoundTrip(req)
				errChan <- err
			}()

			Consistently(errChan, scaleDuration(30*time.Millisecond)).ShouldNot(Receive())
			Expect(tr.Close()).To(Succeed())
			var rtErr error
			Eventually(errChan).Should(Receive(&rtErr))
			Expect(rtErr).To(MatchError("cancelled"))
		})

		It("closes idle connections", func() {
			conn1 := mockquic.NewMockEarlyConnection(mockCtrl)
			conn2 := mockquic.NewMockEarlyConnection(mockCtrl)
			tr := &Transport{
				Dial: func(_ context.Context, hostname string, _ *tls.Config, _ *quic.Config) (quic.EarlyConnection, error) {
					switch hostname {
					case "site1.com:443":
						return conn1, nil
					case "site2.com:443":
						return conn2, nil
					default:
						Fail("unexpected hostname")
						return nil, errors.New("unexpected hostname")
					}
				},
			}
			req1, err := http.NewRequest("GET", "https://site1.com", nil)
			Expect(err).ToNot(HaveOccurred())
			req2, err := http.NewRequest("GET", "https://site2.com", nil)
			Expect(err).ToNot(HaveOccurred())
			Expect(req1.Host).ToNot(Equal(req2.Host))
			ctx1, cancel1 := context.WithCancel(context.Background())
			ctx2, cancel2 := context.WithCancel(context.Background())
			req1 = req1.WithContext(ctx1)
			req2 = req2.WithContext(ctx2)
			roundTripCalled := make(chan struct{})
			reqFinished := make(chan struct{})
			tr.newClient = func(quic.EarlyConnection) singleRoundTripper {
				cl := NewMockSingleRoundTripper(mockCtrl)
				cl.EXPECT().RoundTrip(gomock.Any()).DoAndReturn(func(r *http.Request) (*http.Response, error) {
					roundTripCalled <- struct{}{}
					<-r.Context().Done()
					return nil, nil
				})
				return cl
			}
			go func() {
				tr.RoundTrip(req1)
				reqFinished <- struct{}{}
			}()
			go func() {
				tr.RoundTrip(req2)
				reqFinished <- struct{}{}
			}()
			<-roundTripCalled
			<-roundTripCalled
			// Both two requests are started.
			cancel1()
			<-reqFinished
			// req1 is finished
			conn1.EXPECT().CloseWithError(gomock.Any(), gomock.Any())
			tr.CloseIdleConnections()
			cancel2()
			<-reqFinished
			// all requests are finished
			conn2.EXPECT().CloseWithError(gomock.Any(), gomock.Any())
			tr.CloseIdleConnections()
		})
	})
})
