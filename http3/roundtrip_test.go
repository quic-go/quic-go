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
	"github.com/quic-go/quic-go/internal/qerr"

	"github.com/golang/mock/gomock"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

//go:generate sh -c "./../mockgen_private.sh http3 mock_roundtripcloser_test.go github.com/quic-go/quic-go/http3 roundTripCloser"

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

var _ = Describe("RoundTripper", func() {
	var (
		rt  *RoundTripper
		req *http.Request
	)

	BeforeEach(func() {
		rt = &RoundTripper{}
		var err error
		req, err = http.NewRequest("GET", "https://www.example.org/file1.html", nil)
		Expect(err).ToNot(HaveOccurred())
	})

	Context("dialing hosts", func() {
		It("creates new clients", func() {
			testErr := errors.New("test err")
			req, err := http.NewRequest("GET", "https://quic.clemente.io/foobar.html", nil)
			Expect(err).ToNot(HaveOccurred())
			rt.newClient = func(string, *tls.Config, *roundTripperOpts, *quic.Config, dialFunc) (roundTripCloser, error) {
				cl := NewMockRoundTripCloser(mockCtrl)
				cl.EXPECT().RoundTripOpt(gomock.Any(), gomock.Any()).Return(nil, testErr)
				return cl, nil
			}
			_, err = rt.RoundTrip(req)
			Expect(err).To(MatchError(testErr))
		})

		It("uses the quic.Config, if provided", func() {
			config := &quic.Config{HandshakeIdleTimeout: time.Millisecond}
			var receivedConfig *quic.Config
			dialAddr = func(_ context.Context, _ string, _ *tls.Config, config *quic.Config) (quic.EarlyConnection, error) {
				receivedConfig = config
				return nil, errors.New("handshake error")
			}
			rt.QuicConfig = config
			_, err := rt.RoundTrip(req)
			Expect(err).To(MatchError("handshake error"))
			Expect(receivedConfig.HandshakeIdleTimeout).To(Equal(config.HandshakeIdleTimeout))
		})

		It("uses the custom dialer, if provided", func() {
			var dialed bool
			dialer := func(_ context.Context, _ string, tlsCfgP *tls.Config, cfg *quic.Config) (quic.EarlyConnection, error) {
				dialed = true
				return nil, errors.New("handshake error")
			}
			rt.Dial = dialer
			_, err := rt.RoundTrip(req)
			Expect(err).To(MatchError("handshake error"))
			Expect(dialed).To(BeTrue())
		})
	})

	Context("reusing clients", func() {
		var req1, req2 *http.Request

		BeforeEach(func() {
			var err error
			req1, err = http.NewRequest("GET", "https://quic.clemente.io/file1.html", nil)
			Expect(err).ToNot(HaveOccurred())
			req2, err = http.NewRequest("GET", "https://quic.clemente.io/file2.html", nil)
			Expect(err).ToNot(HaveOccurred())
			Expect(req1.URL).ToNot(Equal(req2.URL))
		})

		It("reuses existing clients", func() {
			var count int
			rt.newClient = func(string, *tls.Config, *roundTripperOpts, *quic.Config, dialFunc) (roundTripCloser, error) {
				count++
				cl := NewMockRoundTripCloser(mockCtrl)
				cl.EXPECT().RoundTripOpt(gomock.Any(), gomock.Any()).DoAndReturn(func(req *http.Request, _ RoundTripOpt) (*http.Response, error) {
					return &http.Response{Request: req}, nil
				}).Times(2)
				cl.EXPECT().HandshakeComplete().Return(true)
				return cl, nil
			}
			rsp1, err := rt.RoundTrip(req1)
			Expect(err).ToNot(HaveOccurred())
			Expect(rsp1.Request.URL).To(Equal(req1.URL))
			rsp2, err := rt.RoundTrip(req2)
			Expect(err).ToNot(HaveOccurred())
			Expect(rsp2.Request.URL).To(Equal(req2.URL))
			Expect(count).To(Equal(1))
		})

		It("immediately removes a clients when a request errored", func() {
			testErr := errors.New("test err")

			var count int
			rt.newClient = func(string, *tls.Config, *roundTripperOpts, *quic.Config, dialFunc) (roundTripCloser, error) {
				count++
				cl := NewMockRoundTripCloser(mockCtrl)
				cl.EXPECT().RoundTripOpt(gomock.Any(), gomock.Any()).Return(nil, testErr)
				return cl, nil
			}
			_, err := rt.RoundTrip(req1)
			Expect(err).To(MatchError(testErr))
			_, err = rt.RoundTrip(req2)
			Expect(err).To(MatchError(testErr))
			Expect(count).To(Equal(2))
		})

		It("recreates a client when a request times out", func() {
			var reqCount int
			cl1 := NewMockRoundTripCloser(mockCtrl)
			cl1.EXPECT().RoundTripOpt(gomock.Any(), gomock.Any()).DoAndReturn(func(req *http.Request, _ RoundTripOpt) (*http.Response, error) {
				reqCount++
				if reqCount == 1 { // the first request is successful...
					Expect(req.URL).To(Equal(req1.URL))
					return &http.Response{Request: req}, nil
				}
				// ... after that, the connection timed out in the background
				Expect(req.URL).To(Equal(req2.URL))
				return nil, &qerr.IdleTimeoutError{}
			}).Times(2)
			cl1.EXPECT().HandshakeComplete().Return(true)
			cl2 := NewMockRoundTripCloser(mockCtrl)
			cl2.EXPECT().RoundTripOpt(gomock.Any(), gomock.Any()).DoAndReturn(func(req *http.Request, _ RoundTripOpt) (*http.Response, error) {
				return &http.Response{Request: req}, nil
			})

			var count int
			rt.newClient = func(string, *tls.Config, *roundTripperOpts, *quic.Config, dialFunc) (roundTripCloser, error) {
				count++
				if count == 1 {
					return cl1, nil
				}
				return cl2, nil
			}
			rsp1, err := rt.RoundTrip(req1)
			Expect(err).ToNot(HaveOccurred())
			Expect(rsp1.Request.RemoteAddr).To(Equal(req1.RemoteAddr))
			rsp2, err := rt.RoundTrip(req2)
			Expect(err).ToNot(HaveOccurred())
			Expect(rsp2.Request.RemoteAddr).To(Equal(req2.RemoteAddr))
		})

		It("only issues a request once, even if a timeout error occurs", func() {
			var count int
			rt.newClient = func(string, *tls.Config, *roundTripperOpts, *quic.Config, dialFunc) (roundTripCloser, error) {
				count++
				cl := NewMockRoundTripCloser(mockCtrl)
				cl.EXPECT().RoundTripOpt(gomock.Any(), gomock.Any()).Return(nil, &qerr.IdleTimeoutError{})
				return cl, nil
			}
			_, err := rt.RoundTrip(req1)
			Expect(err).To(MatchError(&qerr.IdleTimeoutError{}))
			Expect(count).To(Equal(1))
		})

		It("handles a burst of requests", func() {
			wait := make(chan struct{})
			reqs := make(chan struct{}, 2)
			var count int
			rt.newClient = func(string, *tls.Config, *roundTripperOpts, *quic.Config, dialFunc) (roundTripCloser, error) {
				count++
				cl := NewMockRoundTripCloser(mockCtrl)
				cl.EXPECT().RoundTripOpt(gomock.Any(), gomock.Any()).DoAndReturn(func(req *http.Request, _ RoundTripOpt) (*http.Response, error) {
					reqs <- struct{}{}
					<-wait
					return nil, &qerr.IdleTimeoutError{}
				}).Times(2)
				cl.EXPECT().HandshakeComplete()
				return cl, nil
			}
			done := make(chan struct{}, 2)
			go func() {
				defer GinkgoRecover()
				defer func() { done <- struct{}{} }()
				_, err := rt.RoundTrip(req1)
				Expect(err).To(MatchError(&qerr.IdleTimeoutError{}))
			}()
			go func() {
				defer GinkgoRecover()
				defer func() { done <- struct{}{} }()
				_, err := rt.RoundTrip(req2)
				Expect(err).To(MatchError(&qerr.IdleTimeoutError{}))
			}()
			// wait for both requests to be issued
			Eventually(reqs).Should(Receive())
			Eventually(reqs).Should(Receive())
			close(wait) // now return the requests
			Eventually(done).Should(Receive())
			Eventually(done).Should(Receive())
			Expect(count).To(Equal(1))
		})

		It("doesn't create new clients if RoundTripOpt.OnlyCachedConn is set", func() {
			req, err := http.NewRequest("GET", "https://quic.clemente.io/foobar.html", nil)
			Expect(err).ToNot(HaveOccurred())
			_, err = rt.RoundTripOpt(req, RoundTripOpt{OnlyCachedConn: true})
			Expect(err).To(MatchError(ErrNoCachedConn))
		})
	})

	Context("validating request", func() {
		It("rejects plain HTTP requests", func() {
			req, err := http.NewRequest("GET", "http://www.example.org/", nil)
			req.Body = &mockBody{}
			Expect(err).ToNot(HaveOccurred())
			_, err = rt.RoundTrip(req)
			Expect(err).To(MatchError("http3: unsupported protocol scheme: http"))
			Expect(req.Body.(*mockBody).closed).To(BeTrue())
		})

		It("rejects requests without a URL", func() {
			req.URL = nil
			req.Body = &mockBody{}
			_, err := rt.RoundTrip(req)
			Expect(err).To(MatchError("http3: nil Request.URL"))
			Expect(req.Body.(*mockBody).closed).To(BeTrue())
		})

		It("rejects request without a URL Host", func() {
			req.URL.Host = ""
			req.Body = &mockBody{}
			_, err := rt.RoundTrip(req)
			Expect(err).To(MatchError("http3: no Host in request URL"))
			Expect(req.Body.(*mockBody).closed).To(BeTrue())
		})

		It("doesn't try to close the body if the request doesn't have one", func() {
			req.URL = nil
			Expect(req.Body).To(BeNil())
			_, err := rt.RoundTrip(req)
			Expect(err).To(MatchError("http3: nil Request.URL"))
		})

		It("rejects requests without a header", func() {
			req.Header = nil
			req.Body = &mockBody{}
			_, err := rt.RoundTrip(req)
			Expect(err).To(MatchError("http3: nil Request.Header"))
			Expect(req.Body.(*mockBody).closed).To(BeTrue())
		})

		It("rejects requests with invalid header name fields", func() {
			req.Header.Add("foobär", "value")
			_, err := rt.RoundTrip(req)
			Expect(err).To(MatchError("http3: invalid http header field name \"foobär\""))
		})

		It("rejects requests with invalid header name values", func() {
			req.Header.Add("foo", string([]byte{0x7}))
			_, err := rt.RoundTrip(req)
			Expect(err.Error()).To(ContainSubstring("http3: invalid http header field value"))
		})

		It("rejects requests with an invalid request method", func() {
			req.Method = "foobär"
			req.Body = &mockBody{}
			_, err := rt.RoundTrip(req)
			Expect(err).To(MatchError("http3: invalid method \"foobär\""))
			Expect(req.Body.(*mockBody).closed).To(BeTrue())
		})
	})

	Context("closing", func() {
		It("closes", func() {
			rt.clients = make(map[string]roundTripCloser)
			cl := NewMockRoundTripCloser(mockCtrl)
			cl.EXPECT().Close()
			rt.clients["foo.bar"] = cl
			err := rt.Close()
			Expect(err).ToNot(HaveOccurred())
			Expect(len(rt.clients)).To(BeZero())
		})

		It("closes a RoundTripper that has never been used", func() {
			Expect(len(rt.clients)).To(BeZero())
			err := rt.Close()
			Expect(err).ToNot(HaveOccurred())
			Expect(len(rt.clients)).To(BeZero())
		})
	})
})
