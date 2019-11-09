package http3

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/lucas-clemente/quic-go"
	mockquic "github.com/lucas-clemente/quic-go/internal/mocks/quic"
	"github.com/lucas-clemente/quic-go/internal/testdata"
	"github.com/lucas-clemente/quic-go/internal/utils"
	"github.com/marten-seemann/qpack"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Server", func() {
	var (
		s                  *Server
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

			Expect(s.handleRequest(str, qpackDecoder, nil)).To(Equal(requestError{}))
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

			serr := s.handleRequest(str, qpackDecoder, nil)
			Expect(serr.err).ToNot(HaveOccurred())
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

			serr := s.handleRequest(str, qpackDecoder, nil)
			Expect(serr.err).ToNot(HaveOccurred())
			hfs := decodeHeader(responseBuf)
			Expect(hfs).To(HaveKeyWithValue(":status", []string{"500"}))
		})

		Context("stream- and connection-level errors", func() {
			var sess *mockquic.MockSession

			BeforeEach(func() {
				sess = mockquic.NewMockSession(mockCtrl)
				controlStr := mockquic.NewMockStream(mockCtrl)
				controlStr.EXPECT().Write(gomock.Any())
				sess.EXPECT().OpenUniStream().Return(controlStr, nil)
				sess.EXPECT().AcceptStream(gomock.Any()).Return(str, nil)
				sess.EXPECT().AcceptStream(gomock.Any()).Return(nil, errors.New("done"))
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
				done := make(chan struct{})
				str.EXPECT().Context().Return(reqContext)
				str.EXPECT().Write(gomock.Any()).DoAndReturn(func(p []byte) (int, error) {
					return responseBuf.Write(p)
				}).AnyTimes()
				str.EXPECT().CancelRead(quic.ErrorCode(errorEarlyResponse))
				str.EXPECT().Close().Do(func() { close(done) })

				s.handleConn(sess)
				Eventually(done).Should(BeClosed())
				hfs := decodeHeader(responseBuf)
				Expect(hfs).To(HaveKeyWithValue(":status", []string{"200"}))
			})

			It("errors when the client sends a too large header frame", func() {
				s.Server.MaxHeaderBytes = 42
				s.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					Fail("Handler should not be called.")
				})

				requestData := encodeRequest(exampleGetRequest)
				buf := &bytes.Buffer{}
				(&dataFrame{Length: 6}).Write(buf) // add a body
				buf.Write([]byte("foobar"))
				responseBuf := &bytes.Buffer{}
				setRequest(append(requestData, buf.Bytes()...))
				done := make(chan struct{})
				str.EXPECT().Write(gomock.Any()).DoAndReturn(func(p []byte) (int, error) {
					return responseBuf.Write(p)
				}).AnyTimes()
				str.EXPECT().CancelWrite(quic.ErrorCode(errorFrameError)).Do(func(quic.ErrorCode) { close(done) })

				s.handleConn(sess)
				Eventually(done).Should(BeClosed())
			})

			It("handles a request for which the client immediately resets the stream", func() {
				handlerCalled := make(chan struct{})
				s.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					close(handlerCalled)
				})

				testErr := errors.New("stream reset")
				done := make(chan struct{})
				str.EXPECT().Read(gomock.Any()).Return(0, testErr)
				str.EXPECT().CancelWrite(quic.ErrorCode(errorRequestIncomplete)).Do(func(quic.ErrorCode) { close(done) })

				s.handleConn(sess)
				Consistently(handlerCalled).ShouldNot(BeClosed())
			})

			It("closes the connection when the first frame is not a HEADERS frame", func() {
				handlerCalled := make(chan struct{})
				s.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					close(handlerCalled)
				})

				buf := &bytes.Buffer{}
				(&dataFrame{}).Write(buf)
				setRequest(buf.Bytes())
				str.EXPECT().Write(gomock.Any()).DoAndReturn(func(p []byte) (int, error) {
					return len(p), nil
				}).AnyTimes()

				done := make(chan struct{})
				sess.EXPECT().CloseWithError(gomock.Any(), gomock.Any()).Do(func(code quic.ErrorCode, _ string) {
					Expect(code).To(Equal(quic.ErrorCode(errorFrameUnexpected)))
					close(done)
				})
				s.handleConn(sess)
				Eventually(done).Should(BeClosed())
			})

			It("closes the connection when the first frame is not a HEADERS frame", func() {
				handlerCalled := make(chan struct{})
				s.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					close(handlerCalled)
				})

				url := bytes.Repeat([]byte{'a'}, http.DefaultMaxHeaderBytes+1)
				req, err := http.NewRequest(http.MethodGet, "https://"+string(url), nil)
				Expect(err).ToNot(HaveOccurred())
				setRequest(encodeRequest(req))
				// str.EXPECT().Context().Return(reqContext)
				str.EXPECT().Write(gomock.Any()).DoAndReturn(func(p []byte) (int, error) {
					return len(p), nil
				}).AnyTimes()
				done := make(chan struct{})
				str.EXPECT().CancelWrite(quic.ErrorCode(errorFrameError)).Do(func(quic.ErrorCode) { close(done) })

				s.handleConn(sess)
				Eventually(done).Should(BeClosed())
			})
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

			serr := s.handleRequest(str, qpackDecoder, nil)
			Expect(serr.err).ToNot(HaveOccurred())
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

			serr := s.handleRequest(str, qpackDecoder, nil)
			Expect(serr.err).ToNot(HaveOccurred())
			Eventually(handlerCalled).Should(BeClosed())
		})
	})

	Context("setting http headers", func() {
		var expected http.Header

		getExpectedHeader := func() http.Header {
			return http.Header{
				"Alt-Svc": {fmt.Sprintf(`%s=":443"; ma=2592000`, nextProtoH3)},
			}
		}

		BeforeEach(func() {
			Expect(getExpectedHeader()).To(Equal(http.Header{"Alt-Svc": {nextProtoH3 + `=":443"; ma=2592000`}}))
			expected = getExpectedHeader()
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

	It("errors when ListenAndServe is called after Close", func() {
		serv := &Server{Server: &http.Server{}}
		Expect(serv.Close()).To(Succeed())
		Expect(serv.ListenAndServe()).To(MatchError(http.ErrServerClosed))
	})

	Context("Serve", func() {
		origQuicListen := quicListen

		AfterEach(func() {
			quicListen = origQuicListen
		})

		It("serves a packet conn", func() {
			ln := mockquic.NewMockListener(mockCtrl)
			conn := &net.UDPConn{}
			quicListen = func(c net.PacketConn, tlsConf *tls.Config, config *quic.Config) (quic.Listener, error) {
				Expect(c).To(Equal(conn))
				return ln, nil
			}

			s := &Server{Server: &http.Server{}}
			s.TLSConfig = &tls.Config{}

			stopAccept := make(chan struct{})
			ln.EXPECT().Accept(gomock.Any()).DoAndReturn(func(context.Context) (quic.Session, error) {
				<-stopAccept
				return nil, errors.New("closed")
			})
			done := make(chan struct{})
			go func() {
				defer GinkgoRecover()
				defer close(done)
				s.Serve(conn)
			}()

			Consistently(done).ShouldNot(BeClosed())
			ln.EXPECT().Close().Do(func() { close(stopAccept) })
			Expect(s.Close()).To(Succeed())
			Eventually(done).Should(BeClosed())
		})

		It("serves two packet conns", func() {
			ln1 := mockquic.NewMockListener(mockCtrl)
			ln2 := mockquic.NewMockListener(mockCtrl)
			lns := []quic.Listener{ln1, ln2}
			conn1 := &net.UDPConn{}
			conn2 := &net.UDPConn{}
			conns := []net.PacketConn{conn1, conn2}
			quicListen = func(c net.PacketConn, tlsConf *tls.Config, config *quic.Config) (quic.Listener, error) {
				conn := conns[0]
				conns = conns[1:]
				ln := lns[0]
				lns = lns[1:]
				Expect(c).To(Equal(conn))
				return ln, nil
			}

			s := &Server{Server: &http.Server{}}
			s.TLSConfig = &tls.Config{}

			stopAccept1 := make(chan struct{})
			ln1.EXPECT().Accept(gomock.Any()).DoAndReturn(func(context.Context) (quic.Session, error) {
				<-stopAccept1
				return nil, errors.New("closed")
			})
			stopAccept2 := make(chan struct{})
			ln2.EXPECT().Accept(gomock.Any()).DoAndReturn(func(context.Context) (quic.Session, error) {
				<-stopAccept2
				return nil, errors.New("closed")
			})

			done1 := make(chan struct{})
			go func() {
				defer GinkgoRecover()
				defer close(done1)
				s.Serve(conn1)
			}()
			done2 := make(chan struct{})
			go func() {
				defer GinkgoRecover()
				defer close(done2)
				s.Serve(conn2)
			}()

			Consistently(done1).ShouldNot(BeClosed())
			Expect(done2).ToNot(BeClosed())
			ln1.EXPECT().Close().Do(func() { close(stopAccept1) })
			ln2.EXPECT().Close().Do(func() { close(stopAccept2) })
			Expect(s.Close()).To(Succeed())
			Eventually(done1).Should(BeClosed())
			Eventually(done2).Should(BeClosed())
		})
	})

	Context("ListenAndServe", func() {
		BeforeEach(func() {
			s.Server.Addr = "localhost:0"
		})

		AfterEach(func() {
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

		It("replaces the ALPN token to the tls.Config", func() {
			tlsConf := &tls.Config{NextProtos: []string{"foo", "bar"}}
			var receivedConf *tls.Config
			quicListenAddr = func(addr string, tlsConf *tls.Config, _ *quic.Config) (quic.Listener, error) {
				receivedConf = tlsConf
				return nil, errors.New("listen err")
			}
			s.TLSConfig = tlsConf
			Expect(s.ListenAndServe()).To(HaveOccurred())
			Expect(receivedConf.NextProtos).To(Equal([]string{nextProtoH3}))
			// make sure the original tls.Config was not modified
			Expect(tlsConf.NextProtos).To(Equal([]string{"foo", "bar"}))
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

		It("sets the ALPN for tls.Configs returned by the tls.GetConfigForClient", func() {
			tlsConf := &tls.Config{
				GetConfigForClient: func(ch *tls.ClientHelloInfo) (*tls.Config, error) {
					return &tls.Config{NextProtos: []string{"foo", "bar"}}, nil
				},
			}

			var receivedConf *tls.Config
			quicListenAddr = func(addr string, conf *tls.Config, _ *quic.Config) (quic.Listener, error) {
				receivedConf = conf
				return nil, errors.New("listen err")
			}
			s.TLSConfig = tlsConf
			Expect(s.ListenAndServe()).To(HaveOccurred())
			// check that the config used by QUIC uses the h3 ALPN
			conf, err := receivedConf.GetConfigForClient(&tls.ClientHelloInfo{})
			Expect(err).ToNot(HaveOccurred())
			Expect(conf.NextProtos).To(Equal([]string{nextProtoH3}))
			// check that the original config was not modified
			conf, err = tlsConf.GetConfigForClient(&tls.ClientHelloInfo{})
			Expect(err).ToNot(HaveOccurred())
			Expect(conf.NextProtos).To(Equal([]string{"foo", "bar"}))
		})

		It("sets the ALPN for tls.Configs returned by the tls.GetConfigForClient, if it returns a static tls.Config", func() {
			tlsClientConf := &tls.Config{NextProtos: []string{"foo", "bar"}}
			tlsConf := &tls.Config{
				GetConfigForClient: func(ch *tls.ClientHelloInfo) (*tls.Config, error) {
					return tlsClientConf, nil
				},
			}

			var receivedConf *tls.Config
			quicListenAddr = func(addr string, conf *tls.Config, _ *quic.Config) (quic.Listener, error) {
				receivedConf = conf
				return nil, errors.New("listen err")
			}
			s.TLSConfig = tlsConf
			Expect(s.ListenAndServe()).To(HaveOccurred())
			// check that the config used by QUIC uses the h3 ALPN
			conf, err := receivedConf.GetConfigForClient(&tls.ClientHelloInfo{})
			Expect(err).ToNot(HaveOccurred())
			Expect(conf.NextProtos).To(Equal([]string{nextProtoH3}))
			// check that the original config was not modified
			conf, err = tlsConf.GetConfigForClient(&tls.ClientHelloInfo{})
			Expect(err).ToNot(HaveOccurred())
			Expect(conf.NextProtos).To(Equal([]string{"foo", "bar"}))
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
