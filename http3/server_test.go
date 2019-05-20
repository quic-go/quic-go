package http3

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/lucas-clemente/quic-go"
	mockquic "github.com/lucas-clemente/quic-go/internal/mocks/quic"
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/testdata"
	"github.com/lucas-clemente/quic-go/internal/utils"
	"github.com/marten-seemann/qpack"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Server", func() {
	var (
		s *Server
		// session            *mockquic.MockSession
		origQuicListenAddr = quicListenAddr
	)

	BeforeEach(func() {
		s = &Server{
			Server: &http.Server{
				TLSConfig: testdata.GetTLSConfig(),
			},
			logger: utils.DefaultLogger,
		}
		origQuicListenAddr = quicListenAddr
	})

	AfterEach(func() {
		quicListenAddr = origQuicListenAddr
	})

	Context("handling requests", func() {
		var (
			qpackDecoder       *qpack.Decoder
			str                *mockquic.MockStream
			exampleGetRequest  *http.Request
			examplePostRequest *http.Request
		)
		reqContext := context.Background()

		decodeHeader := func(str io.Reader) map[string][]string {
			fields := make(map[string][]string)
			decoder := qpack.NewDecoder(nil)

			frame, err := parseNextFrame(str)
			Expect(err).ToNot(HaveOccurred())
			Expect(frame).To(BeAssignableToTypeOf(&headersFrame{}))
			headersFrame := frame.(*headersFrame)
			data := make([]byte, headersFrame.Length)
			_, err = io.ReadFull(str, data)
			Expect(err).ToNot(HaveOccurred())
			hfs, err := decoder.DecodeFull(data)
			Expect(err).ToNot(HaveOccurred())
			for _, p := range hfs {
				fields[p.Name] = append(fields[p.Name], p.Value)
			}
			return fields
		}

		encodeRequest := func(req *http.Request) []byte {
			buf := &bytes.Buffer{}
			str := mockquic.NewMockStream(mockCtrl)
			str.EXPECT().Write(gomock.Any()).DoAndReturn(func(p []byte) (int, error) {
				return buf.Write(p)
			}).AnyTimes()
			closed := make(chan struct{})
			str.EXPECT().Close().Do(func() { close(closed) })
			rw := newRequestWriter(utils.DefaultLogger)
			Expect(rw.WriteRequest(str, req, false)).To(Succeed())
			Eventually(closed).Should(BeClosed())
			return buf.Bytes()
		}

		setRequest := func(data []byte) {
			buf := bytes.NewBuffer(data)
			str.EXPECT().Read(gomock.Any()).DoAndReturn(func(p []byte) (int, error) {
				if buf.Len() == 0 {
					return 0, io.EOF
				}
				return buf.Read(p)
			}).AnyTimes()
		}

		BeforeEach(func() {
			var err error
			exampleGetRequest, err = http.NewRequest("GET", "https://www.example.com", nil)
			Expect(err).ToNot(HaveOccurred())
			examplePostRequest, err = http.NewRequest("POST", "https://www.example.com", bytes.NewReader([]byte("foobar")))
			Expect(err).ToNot(HaveOccurred())

			qpackDecoder = qpack.NewDecoder(nil)
			str = mockquic.NewMockStream(mockCtrl)
		})

		It("calls the HTTP handler function", func() {
			requestChan := make(chan *http.Request, 1)
			s.Handler = http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
				requestChan <- r
			})

			setRequest(encodeRequest(exampleGetRequest))
			str.EXPECT().Context().Return(reqContext)
			str.EXPECT().Write(gomock.Any()).DoAndReturn(func(p []byte) (int, error) {
				return len(p), nil
			}).AnyTimes()

			Expect(s.handleRequest(str, qpackDecoder)).To(Succeed())
			var req *http.Request
			Eventually(requestChan).Should(Receive(&req))
			Expect(req.Host).To(Equal("www.example.com"))
		})

		It("returns 200 with an empty handler", func() {
			s.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})

			responseBuf := &bytes.Buffer{}
			setRequest(encodeRequest(exampleGetRequest))
			str.EXPECT().Context().Return(reqContext)
			str.EXPECT().Write(gomock.Any()).DoAndReturn(func(p []byte) (int, error) {
				return responseBuf.Write(p)
			}).AnyTimes()

			Expect(s.handleRequest(str, qpackDecoder)).To(Succeed())
			hfs := decodeHeader(responseBuf)
			Expect(hfs).To(HaveKeyWithValue(":status", []string{"200"}))
		})

		It("handles a panicking handler", func() {
			s.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				panic("foobar")
			})

			responseBuf := &bytes.Buffer{}
			setRequest(encodeRequest(exampleGetRequest))
			str.EXPECT().Context().Return(reqContext)
			str.EXPECT().Write(gomock.Any()).DoAndReturn(func(p []byte) (int, error) {
				return responseBuf.Write(p)
			}).AnyTimes()
			str.EXPECT().CancelRead(gomock.Any())

			Expect(s.handleRequest(str, qpackDecoder)).To(Succeed())
			hfs := decodeHeader(responseBuf)
			Expect(hfs).To(HaveKeyWithValue(":status", []string{"500"}))
		})

		It("cancels reading when client sends a body in GET request", func() {
			handlerCalled := make(chan struct{})
			s.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				close(handlerCalled)
			})

			requestData := encodeRequest(exampleGetRequest)
			buf := &bytes.Buffer{}
			(&dataFrame{Length: 6}).Write(buf) // add a body
			buf.Write([]byte("foobar"))
			responseBuf := &bytes.Buffer{}
			setRequest(append(requestData, buf.Bytes()...))
			str.EXPECT().Context().Return(reqContext)
			str.EXPECT().Write(gomock.Any()).DoAndReturn(func(p []byte) (int, error) {
				return responseBuf.Write(p)
			}).AnyTimes()
			str.EXPECT().CancelRead(quic.ErrorCode(errorEarlyResponse))

			Expect(s.handleRequest(str, qpackDecoder)).To(Succeed())
			hfs := decodeHeader(responseBuf)
			Expect(hfs).To(HaveKeyWithValue(":status", []string{"200"}))
		})

		It("cancels reading when the body of POST request is not read", func() {
			handlerCalled := make(chan struct{})
			s.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				Expect(r.Host).To(Equal("www.example.com"))
				Expect(r.Method).To(Equal("POST"))
				close(handlerCalled)
			})

			setRequest(encodeRequest(examplePostRequest))
			str.EXPECT().Context().Return(reqContext)
			str.EXPECT().Write(gomock.Any()).DoAndReturn(func(p []byte) (int, error) {
				return len(p), nil
			}).AnyTimes()
			str.EXPECT().CancelRead(quic.ErrorCode(errorEarlyResponse))

			Expect(s.handleRequest(str, qpackDecoder)).To(Succeed())
			Eventually(handlerCalled).Should(BeClosed())
		})

		It("handles a request for which the client immediately resets the stream", func() {
			handlerCalled := make(chan struct{})
			s.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				close(handlerCalled)
			})

			testErr := errors.New("stream reset")
			str.EXPECT().Read(gomock.Any()).Return(0, testErr)
			str.EXPECT().CancelWrite(quic.ErrorCode(errorRequestCanceled))

			Expect(s.handleRequest(str, qpackDecoder)).To(MatchError(testErr))
			Consistently(handlerCalled).ShouldNot(BeClosed())
		})

		It("resets the stream when the body of POST request is not read, and the request handler replaces the request.Body", func() {
			handlerCalled := make(chan struct{})
			s.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				r.Body = struct {
					io.Reader
					io.Closer
				}{}
				close(handlerCalled)
			})

			setRequest(encodeRequest(examplePostRequest))
			str.EXPECT().Context().Return(reqContext)
			str.EXPECT().Write(gomock.Any()).DoAndReturn(func(p []byte) (int, error) {
				return len(p), nil
			}).AnyTimes()
			str.EXPECT().CancelRead(quic.ErrorCode(errorEarlyResponse))

			Expect(s.handleRequest(str, qpackDecoder)).To(Succeed())
			Eventually(handlerCalled).Should(BeClosed())
		})

		It("cancels the request context when the stream is closed", func() {
			handlerCalled := make(chan struct{})
			s.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				defer GinkgoRecover()
				Expect(r.Context().Done()).To(BeClosed())
				Expect(r.Context().Err()).To(MatchError(context.Canceled))
				close(handlerCalled)
			})
			setRequest(encodeRequest(examplePostRequest))

			reqContext, cancel := context.WithCancel(context.Background())
			cancel()
			str.EXPECT().Context().Return(reqContext)
			str.EXPECT().Write(gomock.Any()).DoAndReturn(func(p []byte) (int, error) {
				return len(p), nil
			}).AnyTimes()
			str.EXPECT().CancelRead(quic.ErrorCode(errorEarlyResponse))

			Expect(s.handleRequest(str, qpackDecoder)).To(Succeed())
			Eventually(handlerCalled).Should(BeClosed())
		})
	})

	Context("setting http headers", func() {
		var expected http.Header

		getExpectedHeader := func(versions []protocol.VersionNumber) http.Header {
			var versionsAsString []string
			for _, v := range versions {
				versionsAsString = append(versionsAsString, v.ToAltSvc())
			}
			return http.Header{
				"Alt-Svc": {fmt.Sprintf(`quic=":443"; ma=2592000; v="%s"`, strings.Join(versionsAsString, ","))},
			}
		}

		BeforeEach(func() {
			Expect(getExpectedHeader([]protocol.VersionNumber{99, 90, 9})).To(Equal(http.Header{"Alt-Svc": {`quic=":443"; ma=2592000; v="99,90,9"`}}))
			expected = getExpectedHeader(protocol.SupportedVersions)
		})

		It("sets proper headers with numeric port", func() {
			s.Server.Addr = ":443"
			hdr := http.Header{}
			Expect(s.SetQuicHeaders(hdr)).To(Succeed())
			Expect(hdr).To(Equal(expected))
		})

		It("sets proper headers with full addr", func() {
			s.Server.Addr = "127.0.0.1:443"
			hdr := http.Header{}
			Expect(s.SetQuicHeaders(hdr)).To(Succeed())
			Expect(hdr).To(Equal(expected))
		})

		It("sets proper headers with string port", func() {
			s.Server.Addr = ":https"
			hdr := http.Header{}
			Expect(s.SetQuicHeaders(hdr)).To(Succeed())
			Expect(hdr).To(Equal(expected))
		})

		It("works multiple times", func() {
			s.Server.Addr = ":https"
			hdr := http.Header{}
			Expect(s.SetQuicHeaders(hdr)).To(Succeed())
			Expect(hdr).To(Equal(expected))
			hdr = http.Header{}
			Expect(s.SetQuicHeaders(hdr)).To(Succeed())
			Expect(hdr).To(Equal(expected))
		})
	})

	It("errors when ListenAndServe is called with s.Server nil", func() {
		Expect((&Server{}).ListenAndServe()).To(MatchError("use of http3.Server without http.Server"))
	})

	It("errors when ListenAndServeTLS is called with s.Server nil", func() {
		Expect((&Server{}).ListenAndServeTLS(testdata.GetCertificatePaths())).To(MatchError("use of http3.Server without http.Server"))
	})

	It("should nop-Close() when s.server is nil", func() {
		Expect((&Server{}).Close()).To(Succeed())
	})

	It("errors when ListenAndServer is called after Close", func() {
		serv := &Server{Server: &http.Server{}}
		Expect(serv.Close()).To(Succeed())
		Expect(serv.ListenAndServe()).To(MatchError("Server is already closed"))
	})

	Context("ListenAndServe", func() {
		BeforeEach(func() {
			s.Server.Addr = "localhost:0"
		})

		AfterEach(func() {
			Expect(s.Close()).To(Succeed())
		})

		It("may only be called once", func() {
			cErr := make(chan error)
			for i := 0; i < 2; i++ {
				go func() {
					defer GinkgoRecover()
					if err := s.ListenAndServe(); err != nil {
						cErr <- err
					}
				}()
			}
			Eventually(cErr).Should(Receive(MatchError("ListenAndServe may only be called once")))
			Expect(s.Close()).To(Succeed())
		})

		It("uses the quic.Config to start the QUIC server", func() {
			conf := &quic.Config{HandshakeTimeout: time.Nanosecond}
			var receivedConf *quic.Config
			quicListenAddr = func(addr string, _ *tls.Config, config *quic.Config) (quic.Listener, error) {
				receivedConf = config
				return nil, errors.New("listen err")
			}
			s.QuicConfig = conf
			Expect(s.ListenAndServe()).To(HaveOccurred())
			Expect(receivedConf).To(Equal(conf))
		})

		It("adds the ALPN token to the tls.Config", func() {
			var receivedConf *tls.Config
			quicListenAddr = func(addr string, tlsConf *tls.Config, _ *quic.Config) (quic.Listener, error) {
				receivedConf = tlsConf
				return nil, errors.New("listen err")
			}
			s.TLSConfig = &tls.Config{NextProtos: []string{"foo", "bar"}}
			Expect(s.ListenAndServe()).To(HaveOccurred())
			Expect(receivedConf.NextProtos).To(Equal([]string{"foo", "bar", nextProtoH3}))
		})

		It("uses the ALPN token if no tls.Config is given", func() {
			var receivedConf *tls.Config
			quicListenAddr = func(addr string, tlsConf *tls.Config, _ *quic.Config) (quic.Listener, error) {
				receivedConf = tlsConf
				return nil, errors.New("listen err")
			}
			Expect(s.ListenAndServe()).To(HaveOccurred())
			Expect(receivedConf.NextProtos).To(Equal([]string{nextProtoH3}))
		})
	})

	Context("ListenAndServeTLS", func() {
		BeforeEach(func() {
			s.Server.Addr = "localhost:0"
		})

		AfterEach(func() {
			Expect(s.Close()).To(Succeed())
		})

		It("may only be called once", func() {
			cErr := make(chan error)
			for i := 0; i < 2; i++ {
				go func() {
					defer GinkgoRecover()
					if err := s.ListenAndServeTLS(testdata.GetCertificatePaths()); err != nil {
						cErr <- err
					}
				}()
			}
			Eventually(cErr).Should(Receive(MatchError("ListenAndServe may only be called once")))
			Expect(s.Close()).To(Succeed())
		})
	})

	It("closes gracefully", func() {
		Expect(s.CloseGracefully(0)).To(Succeed())
	})

	It("errors when listening fails", func() {
		testErr := errors.New("listen error")
		quicListenAddr = func(addr string, tlsConf *tls.Config, config *quic.Config) (quic.Listener, error) {
			return nil, testErr
		}
		fullpem, privkey := testdata.GetCertificatePaths()
		Expect(ListenAndServeQUIC("", fullpem, privkey, nil)).To(MatchError(testErr))
	})
})
