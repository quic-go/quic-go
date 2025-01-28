package http3

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"runtime"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
	mockquic "github.com/quic-go/quic-go/internal/mocks/quic"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/testdata"
	"github.com/quic-go/quic-go/quicvarint"

	"github.com/quic-go/qpack"
	"go.uber.org/mock/gomock"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	gmtypes "github.com/onsi/gomega/types"
)

type mockAddr struct{ addr string }

func (ma *mockAddr) Network() string { return "udp" }
func (ma *mockAddr) String() string  { return ma.addr }

type mockAddrListener struct {
	*MockQUICEarlyListener
	addr *mockAddr
}

func (m *mockAddrListener) Addr() net.Addr {
	_ = m.MockQUICEarlyListener.Addr()
	return m.addr
}

func newMockAddrListener(addr string) *mockAddrListener {
	return &mockAddrListener{
		MockQUICEarlyListener: NewMockQUICEarlyListener(mockCtrl),
		addr:                  &mockAddr{addr: addr},
	}
}

type noPortListener struct {
	*mockAddrListener
}

func (m *noPortListener) Addr() net.Addr {
	_ = m.mockAddrListener.Addr()
	return &net.UnixAddr{
		Net:  "unix",
		Name: "/tmp/quic.sock",
	}
}

var _ = Describe("Server", func() {
	var (
		s                  *Server
		origQuicListenAddr = quicListenAddr
	)
	type testConnContextKey string

	BeforeEach(func() {
		s = &Server{
			TLSConfig: testdata.GetTLSConfig(),
			ConnContext: func(ctx context.Context, c quic.Connection) context.Context {
				return context.WithValue(ctx, testConnContextKey("test"), c)
			},
		}
		s.closeCtx, s.closeCancel = context.WithCancel(context.Background())
		s.graceCtx, s.graceCancel = context.WithCancel(s.closeCtx)
		origQuicListenAddr = quicListenAddr
	})

	AfterEach(func() {
		quicListenAddr = origQuicListenAddr
	})

	Context("handling requests", func() {
		var (
			qpackDecoder       *qpack.Decoder
			str                *mockquic.MockStream
			conn               *connection
			exampleGetRequest  *http.Request
			examplePostRequest *http.Request
		)
		reqContext, reqContextCancel := context.WithCancel(context.Background())

		decodeHeader := func(str io.Reader) map[string][]string {
			fields := make(map[string][]string)
			decoder := qpack.NewDecoder(nil)

			fp := frameParser{r: str}
			frame, err := fp.ParseNext()
			ExpectWithOffset(1, err).ToNot(HaveOccurred())
			ExpectWithOffset(1, frame).To(BeAssignableToTypeOf(&headersFrame{}))
			headersFrame := frame.(*headersFrame)
			data := make([]byte, headersFrame.Length)
			_, err = io.ReadFull(str, data)
			ExpectWithOffset(1, err).ToNot(HaveOccurred())
			hfs, err := decoder.DecodeFull(data)
			ExpectWithOffset(1, err).ToNot(HaveOccurred())
			for _, p := range hfs {
				fields[p.Name] = append(fields[p.Name], p.Value)
			}
			return fields
		}

		encodeRequest := func(req *http.Request) []byte {
			buf := &bytes.Buffer{}
			str := mockquic.NewMockStream(mockCtrl)
			str.EXPECT().Write(gomock.Any()).DoAndReturn(buf.Write).AnyTimes()
			rw := newRequestWriter()
			Expect(rw.WriteRequestHeader(str, req, false)).To(Succeed())
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
			str.EXPECT().Context().Return(reqContext).AnyTimes()
			str.EXPECT().StreamID().AnyTimes()
			qconn := mockquic.NewMockEarlyConnection(mockCtrl)
			addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1337}
			qconn.EXPECT().RemoteAddr().Return(addr).AnyTimes()
			qconn.EXPECT().LocalAddr().AnyTimes()
			qconn.EXPECT().ConnectionState().Return(quic.ConnectionState{}).AnyTimes()
			qconn.EXPECT().Context().Return(context.Background()).AnyTimes()
			conn = newConnection(context.Background(), qconn, false, protocol.PerspectiveServer, nil, 0)
		})

		It("calls the HTTP handler function", func() {
			requestChan := make(chan *http.Request, 1)
			s.Handler = http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
				requestChan <- r
			})

			setRequest(encodeRequest(exampleGetRequest))
			str.EXPECT().Write(gomock.Any()).DoAndReturn(func(p []byte) (int, error) {
				return len(p), nil
			}).AnyTimes()
			str.EXPECT().CancelRead(gomock.Any())
			str.EXPECT().Close()

			s.handleRequest(conn, str, nil, qpackDecoder)
			var req *http.Request
			Eventually(requestChan).Should(Receive(&req))
			Expect(req.Host).To(Equal("www.example.com"))
			Expect(req.RemoteAddr).To(Equal("127.0.0.1:1337"))
		})

		It("returns 200 with an empty handler", func() {
			s.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})

			responseBuf := &bytes.Buffer{}
			setRequest(encodeRequest(exampleGetRequest))
			str.EXPECT().Write(gomock.Any()).DoAndReturn(responseBuf.Write).AnyTimes()
			str.EXPECT().CancelRead(gomock.Any())
			str.EXPECT().Close()

			s.handleRequest(conn, str, nil, qpackDecoder)
			hfs := decodeHeader(responseBuf)
			Expect(hfs).To(HaveKeyWithValue(":status", []string{"200"}))
		})

		It("sets Content-Length when the handler doesn't flush to the client", func() {
			s.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Write([]byte("foobar"))
			})

			responseBuf := &bytes.Buffer{}
			setRequest(encodeRequest(exampleGetRequest))
			str.EXPECT().Write(gomock.Any()).DoAndReturn(responseBuf.Write).AnyTimes()
			str.EXPECT().CancelRead(gomock.Any())
			str.EXPECT().Close()

			s.handleRequest(conn, str, nil, qpackDecoder)
			hfs := decodeHeader(responseBuf)
			Expect(hfs).To(HaveKeyWithValue(":status", []string{"200"}))
			Expect(hfs).To(HaveKeyWithValue("content-length", []string{"6"}))
			// status, content-length, date, content-type
			Expect(hfs).To(HaveLen(4))
		})

		It("sets Content-Type when WriteHeader is called but response is not flushed", func() {
			s.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusNotFound)
				w.Write([]byte("<html></html>"))
			})

			responseBuf := &bytes.Buffer{}
			setRequest(encodeRequest(exampleGetRequest))
			str.EXPECT().Write(gomock.Any()).DoAndReturn(responseBuf.Write).AnyTimes()
			str.EXPECT().CancelRead(gomock.Any())
			str.EXPECT().Close()

			s.handleRequest(conn, str, nil, qpackDecoder)
			hfs := decodeHeader(responseBuf)
			Expect(hfs).To(HaveKeyWithValue(":status", []string{"404"}))
			Expect(hfs).To(HaveKeyWithValue("content-length", []string{"13"}))
			Expect(hfs).To(HaveKeyWithValue("content-type", []string{"text/html; charset=utf-8"}))
		})

		It("not sets Content-Length when the handler flushes to the client", func() {
			s.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Write([]byte("foobar"))
				// force flush
				w.(http.Flusher).Flush()
			})

			responseBuf := &bytes.Buffer{}
			setRequest(encodeRequest(exampleGetRequest))
			str.EXPECT().Write(gomock.Any()).DoAndReturn(responseBuf.Write).AnyTimes()
			str.EXPECT().CancelRead(gomock.Any())
			str.EXPECT().Close()

			s.handleRequest(conn, str, nil, qpackDecoder)
			hfs := decodeHeader(responseBuf)
			Expect(hfs).To(HaveKeyWithValue(":status", []string{"200"}))
			// status, date, content-type
			Expect(hfs).To(HaveLen(3))
		})

		It("ignores calls to Write for responses to HEAD requests", func() {
			s.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Write([]byte("foobar"))
			})

			headRequest, err := http.NewRequest(http.MethodHead, "https://www.example.com", nil)
			Expect(err).ToNot(HaveOccurred())
			responseBuf := &bytes.Buffer{}
			setRequest(encodeRequest(headRequest))
			str.EXPECT().Write(gomock.Any()).DoAndReturn(responseBuf.Write).AnyTimes()
			str.EXPECT().CancelRead(gomock.Any())
			str.EXPECT().Close()

			s.handleRequest(conn, str, nil, qpackDecoder)
			hfs := decodeHeader(responseBuf)
			Expect(hfs).To(HaveKeyWithValue(":status", []string{"200"}))
			Expect(responseBuf.Bytes()).To(BeEmpty())
		})

		It("response to HEAD request should also do content sniffing", func() {
			s.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Write([]byte("<html></html>"))
			})

			headRequest, err := http.NewRequest(http.MethodHead, "https://www.example.com", nil)
			Expect(err).ToNot(HaveOccurred())
			responseBuf := &bytes.Buffer{}
			setRequest(encodeRequest(headRequest))
			str.EXPECT().Write(gomock.Any()).DoAndReturn(responseBuf.Write).AnyTimes()
			str.EXPECT().CancelRead(gomock.Any())
			str.EXPECT().Close()

			s.handleRequest(conn, str, nil, qpackDecoder)
			hfs := decodeHeader(responseBuf)
			Expect(hfs).To(HaveKeyWithValue(":status", []string{"200"}))
			Expect(hfs).To(HaveKeyWithValue("content-length", []string{"13"}))
			Expect(hfs).To(HaveKeyWithValue("content-type", []string{"text/html; charset=utf-8"}))
		})

		It("handles an aborting handler", func() {
			s.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				panic(http.ErrAbortHandler)
			})

			responseBuf := &bytes.Buffer{}
			setRequest(encodeRequest(exampleGetRequest))
			str.EXPECT().Write(gomock.Any()).DoAndReturn(responseBuf.Write).AnyTimes()
			str.EXPECT().CancelRead(quic.StreamErrorCode(ErrCodeInternalError))
			str.EXPECT().CancelWrite(quic.StreamErrorCode(ErrCodeInternalError))

			s.handleRequest(conn, str, nil, qpackDecoder)
			Expect(responseBuf.Bytes()).To(HaveLen(0))
		})

		It("handles a panicking handler", func() {
			var logBuf bytes.Buffer
			s.Logger = slog.New(slog.NewTextHandler(&logBuf, nil))
			s.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				panic("foobar")
			})

			responseBuf := &bytes.Buffer{}
			setRequest(encodeRequest(exampleGetRequest))
			str.EXPECT().Write(gomock.Any()).DoAndReturn(responseBuf.Write).AnyTimes()
			str.EXPECT().CancelRead(quic.StreamErrorCode(ErrCodeInternalError))
			str.EXPECT().CancelWrite(quic.StreamErrorCode(ErrCodeInternalError))

			s.handleRequest(conn, str, nil, qpackDecoder)
			Expect(responseBuf.Bytes()).To(HaveLen(0))
			Expect(logBuf.String()).To(ContainSubstring("http3: panic serving"))
			Expect(logBuf.String()).To(ContainSubstring("foobar"))
		})

		Context("hijacking bidirectional streams", func() {
			var conn *mockquic.MockEarlyConnection
			testDone := make(chan struct{})

			BeforeEach(func() {
				testDone = make(chan struct{})
				conn = mockquic.NewMockEarlyConnection(mockCtrl)
				controlStr := mockquic.NewMockStream(mockCtrl)
				controlStr.EXPECT().Write(gomock.Any())
				conn.EXPECT().OpenUniStream().Return(controlStr, nil)
				conn.EXPECT().RemoteAddr().Return(&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1337}).AnyTimes()
				conn.EXPECT().LocalAddr().AnyTimes()
			})

			AfterEach(func() { testDone <- struct{}{} })

			It("hijacks a bidirectional stream of unknown frame type", func() {
				id := quic.ConnectionTracingID(1337)
				frameTypeChan := make(chan FrameType, 1)
				s.StreamHijacker = func(ft FrameType, connTracingID quic.ConnectionTracingID, _ quic.Stream, e error) (hijacked bool, err error) {
					defer GinkgoRecover()
					Expect(e).ToNot(HaveOccurred())
					Expect(connTracingID).To(Equal(id))
					frameTypeChan <- ft
					return true, nil
				}

				buf := bytes.NewBuffer(quicvarint.Append(nil, 0x41))
				unknownStr := mockquic.NewMockStream(mockCtrl)
				unknownStr.EXPECT().Context().Return(context.Background()).AnyTimes()
				unknownStr.EXPECT().Read(gomock.Any()).DoAndReturn(buf.Read).AnyTimes()
				unknownStr.EXPECT().StreamID().AnyTimes()
				conn.EXPECT().AcceptStream(gomock.Any()).Return(unknownStr, nil)
				conn.EXPECT().AcceptStream(gomock.Any()).Return(nil, errors.New("done"))
				conn.EXPECT().AcceptUniStream(gomock.Any()).DoAndReturn(func(context.Context) (quic.ReceiveStream, error) {
					<-testDone
					return nil, errors.New("test done")
				})
				ctx := context.WithValue(context.Background(), quic.ConnectionTracingKey, id)
				conn.EXPECT().Context().Return(ctx).AnyTimes()
				s.handleConn(conn)
				Eventually(frameTypeChan).Should(Receive(BeEquivalentTo(0x41)))
				time.Sleep(scaleDuration(20 * time.Millisecond)) // don't EXPECT any calls to conn.CloseWithError
			})

			It("cancels writing when hijacker didn't hijack a bidirectional stream", func() {
				frameTypeChan := make(chan FrameType, 1)
				s.StreamHijacker = func(ft FrameType, _ quic.ConnectionTracingID, _ quic.Stream, e error) (hijacked bool, err error) {
					Expect(e).ToNot(HaveOccurred())
					frameTypeChan <- ft
					return false, nil
				}

				buf := bytes.NewBuffer(quicvarint.Append(nil, 0x41))
				unknownStr := mockquic.NewMockStream(mockCtrl)
				unknownStr.EXPECT().Context().Return(context.Background()).AnyTimes()
				unknownStr.EXPECT().StreamID().AnyTimes()
				unknownStr.EXPECT().Read(gomock.Any()).DoAndReturn(buf.Read).AnyTimes()
				unknownStr.EXPECT().CancelRead(quic.StreamErrorCode(ErrCodeRequestIncomplete))
				unknownStr.EXPECT().CancelWrite(quic.StreamErrorCode(ErrCodeRequestIncomplete))
				conn.EXPECT().AcceptStream(gomock.Any()).Return(unknownStr, nil)
				conn.EXPECT().AcceptStream(gomock.Any()).Return(nil, errors.New("done"))
				conn.EXPECT().AcceptUniStream(gomock.Any()).DoAndReturn(func(context.Context) (quic.ReceiveStream, error) {
					<-testDone
					return nil, errors.New("test done")
				})
				ctx := context.WithValue(context.Background(), quic.ConnectionTracingKey, quic.ConnectionTracingID(1234))
				conn.EXPECT().Context().Return(ctx).AnyTimes()
				s.handleConn(conn)
				Eventually(frameTypeChan).Should(Receive(BeEquivalentTo(0x41)))
				time.Sleep(scaleDuration(20 * time.Millisecond)) // don't EXPECT any calls to conn.CloseWithError
			})

			It("cancels writing when hijacker returned error", func() {
				frameTypeChan := make(chan FrameType, 1)
				s.StreamHijacker = func(ft FrameType, _ quic.ConnectionTracingID, _ quic.Stream, e error) (hijacked bool, err error) {
					Expect(e).ToNot(HaveOccurred())
					frameTypeChan <- ft
					return false, errors.New("error in hijacker")
				}

				buf := bytes.NewBuffer(quicvarint.Append(nil, 0x41))
				unknownStr := mockquic.NewMockStream(mockCtrl)
				unknownStr.EXPECT().Context().Return(context.Background()).AnyTimes()
				unknownStr.EXPECT().StreamID().AnyTimes()
				unknownStr.EXPECT().Read(gomock.Any()).DoAndReturn(buf.Read).AnyTimes()
				unknownStr.EXPECT().CancelRead(quic.StreamErrorCode(ErrCodeRequestIncomplete))
				unknownStr.EXPECT().CancelWrite(quic.StreamErrorCode(ErrCodeRequestIncomplete))
				conn.EXPECT().AcceptStream(gomock.Any()).Return(unknownStr, nil)
				conn.EXPECT().AcceptStream(gomock.Any()).Return(nil, errors.New("done"))
				conn.EXPECT().AcceptUniStream(gomock.Any()).DoAndReturn(func(context.Context) (quic.ReceiveStream, error) {
					<-testDone
					return nil, errors.New("test done")
				})
				ctx := context.WithValue(context.Background(), quic.ConnectionTracingKey, quic.ConnectionTracingID(1234))
				conn.EXPECT().Context().Return(ctx).AnyTimes()
				s.handleConn(conn)
				Eventually(frameTypeChan).Should(Receive(BeEquivalentTo(0x41)))
				time.Sleep(scaleDuration(20 * time.Millisecond)) // don't EXPECT any calls to conn.CloseWithError
			})

			It("handles errors that occur when reading the stream type", func() {
				const strID = protocol.StreamID(1234 * 4)
				testErr := errors.New("test error")
				done := make(chan struct{})
				s.StreamHijacker = func(ft FrameType, _ quic.ConnectionTracingID, str quic.Stream, err error) (bool, error) {
					defer close(done)
					Expect(ft).To(BeZero())
					Expect(str.StreamID()).To(Equal(strID))
					Expect(err).To(MatchError(testErr))
					return true, nil
				}
				unknownStr := mockquic.NewMockStream(mockCtrl)
				unknownStr.EXPECT().Context().Return(context.Background()).AnyTimes()
				unknownStr.EXPECT().StreamID().Return(strID).AnyTimes()
				unknownStr.EXPECT().Read(gomock.Any()).Return(0, testErr).AnyTimes()
				conn.EXPECT().AcceptStream(gomock.Any()).Return(unknownStr, nil)
				conn.EXPECT().AcceptStream(gomock.Any()).Return(nil, errors.New("done"))
				conn.EXPECT().AcceptUniStream(gomock.Any()).DoAndReturn(func(context.Context) (quic.ReceiveStream, error) {
					<-testDone
					return nil, errors.New("test done")
				})
				ctx := context.WithValue(context.Background(), quic.ConnectionTracingKey, quic.ConnectionTracingID(1234))
				conn.EXPECT().Context().Return(ctx).AnyTimes()
				s.handleConn(conn)
				Eventually(done).Should(BeClosed())
				time.Sleep(scaleDuration(20 * time.Millisecond)) // don't EXPECT any calls to conn.CloseWithError
			})
		})

		Context("hijacking unidirectional streams", func() {
			var conn *mockquic.MockEarlyConnection
			testDone := make(chan struct{})

			BeforeEach(func() {
				testDone = make(chan struct{})
				conn = mockquic.NewMockEarlyConnection(mockCtrl)
				controlStr := mockquic.NewMockStream(mockCtrl)
				controlStr.EXPECT().Write(gomock.Any())
				conn.EXPECT().OpenUniStream().Return(controlStr, nil)
				conn.EXPECT().AcceptStream(gomock.Any()).Return(nil, errors.New("done"))
				conn.EXPECT().RemoteAddr().Return(&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1337}).AnyTimes()
				conn.EXPECT().LocalAddr().AnyTimes()
			})

			AfterEach(func() { testDone <- struct{}{} })

			It("hijacks an unidirectional stream of unknown stream type", func() {
				id := quic.ConnectionTracingID(42)
				streamTypeChan := make(chan StreamType, 1)
				s.UniStreamHijacker = func(st StreamType, connTracingID quic.ConnectionTracingID, _ quic.ReceiveStream, err error) bool {
					Expect(err).ToNot(HaveOccurred())
					Expect(connTracingID).To(Equal(id))
					streamTypeChan <- st
					return true
				}

				buf := bytes.NewBuffer(quicvarint.Append(nil, 0x54))
				unknownStr := mockquic.NewMockStream(mockCtrl)
				unknownStr.EXPECT().Read(gomock.Any()).DoAndReturn(buf.Read).AnyTimes()
				conn.EXPECT().AcceptUniStream(gomock.Any()).DoAndReturn(func(context.Context) (quic.ReceiveStream, error) {
					return unknownStr, nil
				})
				conn.EXPECT().AcceptUniStream(gomock.Any()).DoAndReturn(func(context.Context) (quic.ReceiveStream, error) {
					<-testDone
					return nil, errors.New("test done")
				})
				ctx := context.WithValue(context.Background(), quic.ConnectionTracingKey, id)
				conn.EXPECT().Context().Return(ctx).AnyTimes()
				s.handleConn(conn)
				Eventually(streamTypeChan).Should(Receive(BeEquivalentTo(0x54)))
				time.Sleep(scaleDuration(20 * time.Millisecond)) // don't EXPECT any calls to conn.CloseWithError
			})

			It("handles errors that occur when reading the stream type", func() {
				testErr := errors.New("test error")
				done := make(chan struct{})
				unknownStr := mockquic.NewMockStream(mockCtrl)
				s.UniStreamHijacker = func(st StreamType, _ quic.ConnectionTracingID, str quic.ReceiveStream, err error) bool {
					defer close(done)
					Expect(st).To(BeZero())
					Expect(str).To(Equal(unknownStr))
					Expect(err).To(MatchError(testErr))
					return true
				}

				unknownStr.EXPECT().Read(gomock.Any()).DoAndReturn(func([]byte) (int, error) { return 0, testErr })
				conn.EXPECT().AcceptUniStream(gomock.Any()).Return(unknownStr, nil)
				conn.EXPECT().AcceptUniStream(gomock.Any()).DoAndReturn(func(context.Context) (quic.ReceiveStream, error) {
					<-testDone
					return nil, errors.New("test done")
				})
				ctx := context.WithValue(context.Background(), quic.ConnectionTracingKey, quic.ConnectionTracingID(1234))
				conn.EXPECT().Context().Return(ctx).AnyTimes()
				s.handleConn(conn)
				Eventually(done).Should(BeClosed())
				time.Sleep(scaleDuration(20 * time.Millisecond)) // don't EXPECT any calls to conn.CloseWithError
			})

			It("cancels reading when hijacker didn't hijack an unidirectional stream", func() {
				streamTypeChan := make(chan StreamType, 1)
				s.UniStreamHijacker = func(st StreamType, _ quic.ConnectionTracingID, _ quic.ReceiveStream, err error) bool {
					Expect(err).ToNot(HaveOccurred())
					streamTypeChan <- st
					return false
				}

				buf := bytes.NewBuffer(quicvarint.Append(nil, 0x54))
				unknownStr := mockquic.NewMockStream(mockCtrl)
				unknownStr.EXPECT().Read(gomock.Any()).DoAndReturn(buf.Read).AnyTimes()
				unknownStr.EXPECT().CancelRead(quic.StreamErrorCode(ErrCodeStreamCreationError))

				conn.EXPECT().AcceptUniStream(gomock.Any()).DoAndReturn(func(context.Context) (quic.ReceiveStream, error) {
					return unknownStr, nil
				})
				conn.EXPECT().AcceptUniStream(gomock.Any()).DoAndReturn(func(context.Context) (quic.ReceiveStream, error) {
					<-testDone
					return nil, errors.New("test done")
				})
				ctx := context.WithValue(context.Background(), quic.ConnectionTracingKey, quic.ConnectionTracingID(1234))
				conn.EXPECT().Context().Return(ctx).AnyTimes()
				s.handleConn(conn)
				Eventually(streamTypeChan).Should(Receive(BeEquivalentTo(0x54)))
				time.Sleep(scaleDuration(20 * time.Millisecond)) // don't EXPECT any calls to conn.CloseWithError
			})
		})

		Context("stream- and connection-level errors", func() {
			var conn *mockquic.MockEarlyConnection
			testDone := make(chan struct{})

			BeforeEach(func() {
				testDone = make(chan struct{})
				addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1337}
				conn = mockquic.NewMockEarlyConnection(mockCtrl)
				controlStr := mockquic.NewMockStream(mockCtrl)
				controlStr.EXPECT().Write(gomock.Any())
				conn.EXPECT().Context().Return(context.Background())
				conn.EXPECT().OpenUniStream().Return(controlStr, nil)
				conn.EXPECT().AcceptUniStream(gomock.Any()).DoAndReturn(func(context.Context) (quic.ReceiveStream, error) {
					<-testDone
					return nil, errors.New("test done")
				})
				conn.EXPECT().AcceptStream(gomock.Any()).Return(str, nil)
				conn.EXPECT().AcceptStream(gomock.Any()).Return(nil, errors.New("done"))
				conn.EXPECT().RemoteAddr().Return(addr).AnyTimes()
				conn.EXPECT().LocalAddr().AnyTimes()
				conn.EXPECT().ConnectionState().Return(quic.ConnectionState{}).AnyTimes()
				conn.EXPECT().Context().Return(context.Background()).AnyTimes()
			})

			AfterEach(func() { testDone <- struct{}{} })

			It("cancels reading when client sends a body in GET request", func() {
				var handlerCalled bool
				s.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					handlerCalled = true
				})

				requestData := encodeRequest(exampleGetRequest)
				b := (&dataFrame{Length: 6}).Append(nil) // add a body
				b = append(b, []byte("foobar")...)
				responseBuf := &bytes.Buffer{}
				setRequest(append(requestData, b...))
				done := make(chan struct{})
				str.EXPECT().Write(gomock.Any()).DoAndReturn(responseBuf.Write).AnyTimes()
				str.EXPECT().CancelRead(quic.StreamErrorCode(ErrCodeNoError))
				str.EXPECT().Close().Do(func() error { close(done); return nil })

				s.handleConn(conn)
				Eventually(done).Should(BeClosed())
				hfs := decodeHeader(responseBuf)
				Expect(hfs).To(HaveKeyWithValue(":status", []string{"200"}))
				Expect(handlerCalled).To(BeTrue())
			})

			It("doesn't close the stream if the stream was hijacked (via HTTPStream)", func() {
				handlerCalled := make(chan struct{})
				s.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					defer close(handlerCalled)
					w.(HTTPStreamer).HTTPStream()
					str.Write([]byte("foobar"))
				})

				requestData := encodeRequest(exampleGetRequest)
				b := (&dataFrame{Length: 6}).Append(nil) // add a body
				b = append(b, []byte("foobar")...)
				setRequest(append(requestData, b...))
				var buf bytes.Buffer
				str.EXPECT().Write(gomock.Any()).DoAndReturn(buf.Write).AnyTimes()

				s.handleConn(conn)
				Eventually(handlerCalled).Should(BeClosed())

				// The buffer is expected to contain:
				// 1. The response header (in a HEADERS frame)
				// 2. the "foobar" (unframed)
				fp := frameParser{r: &buf}
				frame, err := fp.ParseNext()
				Expect(err).ToNot(HaveOccurred())
				Expect(frame).To(BeAssignableToTypeOf(&headersFrame{}))
				df := frame.(*headersFrame)
				data := make([]byte, df.Length)
				_, err = io.ReadFull(&buf, data)
				Expect(err).ToNot(HaveOccurred())
				hdrs, err := qpackDecoder.DecodeFull(data)
				Expect(err).ToNot(HaveOccurred())
				Expect(hdrs).To(ContainElement(qpack.HeaderField{Name: ":status", Value: "200"}))
				Expect(buf.Bytes()).To(Equal([]byte("foobar")))
			})

			It("errors when the client sends a too large header frame", func() {
				s.MaxHeaderBytes = 20
				s.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					Fail("Handler should not be called.")
				})

				requestData := encodeRequest(exampleGetRequest)
				b := (&dataFrame{Length: 6}).Append(nil) // add a body
				b = append(b, []byte("foobar")...)
				responseBuf := &bytes.Buffer{}
				setRequest(append(requestData, b...))
				done := make(chan struct{})
				str.EXPECT().Write(gomock.Any()).DoAndReturn(responseBuf.Write).AnyTimes()
				str.EXPECT().CancelRead(quic.StreamErrorCode(ErrCodeFrameError))
				str.EXPECT().CancelWrite(quic.StreamErrorCode(ErrCodeFrameError)).Do(func(quic.StreamErrorCode) { close(done) })

				s.handleConn(conn)
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
				str.EXPECT().CancelRead(quic.StreamErrorCode(ErrCodeRequestIncomplete))
				str.EXPECT().CancelWrite(quic.StreamErrorCode(ErrCodeRequestIncomplete)).Do(func(quic.StreamErrorCode) { close(done) })

				s.handleConn(conn)
				Consistently(handlerCalled).ShouldNot(BeClosed())
			})

			It("closes the connection when the first frame is not a HEADERS frame", func() {
				handlerCalled := make(chan struct{})
				s.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					close(handlerCalled)
				})

				b := (&dataFrame{}).Append(nil)
				setRequest(b)
				str.EXPECT().Write(gomock.Any()).DoAndReturn(func(p []byte) (int, error) {
					return len(p), nil
				}).AnyTimes()

				done := make(chan struct{})
				conn.EXPECT().CloseWithError(quic.ApplicationErrorCode(ErrCodeFrameUnexpected), gomock.Any()).Do(func(quic.ApplicationErrorCode, string) error {
					close(done)
					return nil
				})
				s.handleConn(conn)
				Eventually(done).Should(BeClosed())
			})

			It("rejects a request that has too large request headers", func() {
				handlerCalled := make(chan struct{})
				s.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					close(handlerCalled)
				})

				// use 2*DefaultMaxHeaderBytes here. qpack will compress the request,
				// but the request will still end up larger than DefaultMaxHeaderBytes.
				url := bytes.Repeat([]byte{'a'}, http.DefaultMaxHeaderBytes*2)
				req, err := http.NewRequest(http.MethodGet, "https://"+string(url), nil)
				Expect(err).ToNot(HaveOccurred())
				setRequest(encodeRequest(req))
				str.EXPECT().Write(gomock.Any()).DoAndReturn(func(p []byte) (int, error) {
					return len(p), nil
				}).AnyTimes()
				done := make(chan struct{})
				str.EXPECT().CancelRead(quic.StreamErrorCode(ErrCodeFrameError))
				str.EXPECT().CancelWrite(quic.StreamErrorCode(ErrCodeFrameError)).Do(func(quic.StreamErrorCode) { close(done) })

				s.handleConn(conn)
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
			str.EXPECT().Write(gomock.Any()).DoAndReturn(func(p []byte) (int, error) {
				return len(p), nil
			}).AnyTimes()
			str.EXPECT().CancelRead(quic.StreamErrorCode(ErrCodeNoError))
			str.EXPECT().Close()

			s.handleRequest(conn, str, nil, qpackDecoder)
			Eventually(handlerCalled).Should(BeClosed())
		})

		It("cancels the request context when the stream is closed", func() {
			handlerCalled := make(chan struct{})
			s.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				defer GinkgoRecover()
				// The context is canceled via context.AfterFunc,
				// which performs the cancellation in a new Go routine.
				Eventually(r.Context().Done()).Should(BeClosed())
				Expect(r.Context().Err()).To(MatchError(context.Canceled))
				close(handlerCalled)
			})
			setRequest(encodeRequest(examplePostRequest))

			reqContextCancel()
			str.EXPECT().Write(gomock.Any()).DoAndReturn(func(p []byte) (int, error) {
				return len(p), nil
			}).AnyTimes()
			str.EXPECT().CancelRead(quic.StreamErrorCode(ErrCodeNoError))
			str.EXPECT().Close()

			s.handleRequest(conn, str, nil, qpackDecoder)
			Eventually(handlerCalled).Should(BeClosed())
		})
	})

	Context("setting http headers", func() {
		BeforeEach(func() {
			s.QUICConfig = &quic.Config{Versions: []protocol.Version{protocol.Version1}}
		})

		var ln1 QUICEarlyListener
		var ln2 QUICEarlyListener
		expected := http.Header{
			"Alt-Svc": {`h3=":443"; ma=2592000`},
		}

		addListener := func(addr string, ln *QUICEarlyListener) {
			mln := newMockAddrListener(addr)
			mln.EXPECT().Addr()
			*ln = mln
			s.addListener(ln)
		}

		removeListener := func(ln *QUICEarlyListener) {
			s.removeListener(ln)
		}

		checkSetHeaders := func(expected gmtypes.GomegaMatcher) {
			hdr := http.Header{}
			Expect(s.SetQUICHeaders(hdr)).To(Succeed())
			Expect(hdr).To(expected)
		}

		checkSetHeaderError := func() {
			hdr := http.Header{}
			Expect(s.SetQUICHeaders(hdr)).To(Equal(ErrNoAltSvcPort))
		}

		It("sets proper headers with numeric port", func() {
			addListener(":443", &ln1)
			checkSetHeaders(Equal(expected))
			removeListener(&ln1)
			checkSetHeaderError()
		})

		It("sets proper headers with full addr", func() {
			addListener("127.0.0.1:443", &ln1)
			checkSetHeaders(Equal(expected))
			removeListener(&ln1)
			checkSetHeaderError()
		})

		It("sets proper headers with string port", func() {
			addListener(":https", &ln1)
			checkSetHeaders(Equal(expected))
			removeListener(&ln1)
			checkSetHeaderError()
		})

		It("works multiple times", func() {
			addListener(":https", &ln1)
			checkSetHeaders(Equal(expected))
			checkSetHeaders(Equal(expected))
			removeListener(&ln1)
			checkSetHeaderError()
		})

		It("works if the quic.Config sets QUIC versions", func() {
			s.QUICConfig.Versions = []quic.Version{quic.Version1, quic.Version2}
			addListener(":443", &ln1)
			checkSetHeaders(Equal(http.Header{"Alt-Svc": {`h3=":443"; ma=2592000`}}))
			removeListener(&ln1)
			checkSetHeaderError()
		})

		It("uses s.Port if set to a non-zero value", func() {
			s.Port = 8443
			addListener(":443", &ln1)
			checkSetHeaders(Equal(http.Header{"Alt-Svc": {`h3=":8443"; ma=2592000`}}))
			removeListener(&ln1)
			checkSetHeaderError()
		})

		It("uses s.Addr if listeners don't have ports available", func() {
			s.Addr = ":443"
			var logBuf bytes.Buffer
			s.Logger = slog.New(slog.NewTextHandler(&logBuf, nil))
			mln := &noPortListener{newMockAddrListener("")}
			mln.EXPECT().Addr()
			ln1 = mln
			s.addListener(&ln1)
			checkSetHeaders(Equal(expected))
			s.removeListener(&ln1)
			checkSetHeaderError()
			Expect(logBuf.String()).To(ContainSubstring("Unable to extract port from listener, will not be announced using SetQUICHeaders"))
		})

		It("properly announces multiple listeners", func() {
			addListener(":443", &ln1)
			addListener(":8443", &ln2)
			checkSetHeaders(Or(
				Equal(http.Header{"Alt-Svc": {`h3=":443"; ma=2592000,h3=":8443"; ma=2592000`}}),
				Equal(http.Header{"Alt-Svc": {`h3=":8443"; ma=2592000,h3=":443"; ma=2592000`}}),
			))
			removeListener(&ln1)
			removeListener(&ln2)
			checkSetHeaderError()
		})

		It("doesn't duplicate Alt-Svc values", func() {
			s.QUICConfig.Versions = []quic.Version{quic.Version1, quic.Version1}
			addListener(":443", &ln1)
			checkSetHeaders(Equal(http.Header{"Alt-Svc": {`h3=":443"; ma=2592000`}}))
			removeListener(&ln1)
			checkSetHeaderError()
		})
	})

	It("errors when ListenAndServe is called with s.TLSConfig nil", func() {
		Expect((&Server{}).ListenAndServe()).To(MatchError(errServerWithoutTLSConfig))
	})

	It("should nop-Close() when s.server is nil", func() {
		Expect((&Server{}).Close()).To(Succeed())
	})

	It("errors when ListenAndServeTLS is called after Close", func() {
		serv := &Server{}
		Expect(serv.Close()).To(Succeed())
		Expect(serv.ListenAndServeTLS(testdata.GetCertificatePaths())).To(MatchError(http.ErrServerClosed))
	})

	It("handles concurrent Serve and Close", func() {
		addr, err := net.ResolveUDPAddr("udp", "localhost:0")
		Expect(err).ToNot(HaveOccurred())
		c, err := net.ListenUDP("udp", addr)
		Expect(err).ToNot(HaveOccurred())
		done := make(chan struct{})
		go func() {
			defer GinkgoRecover()
			defer close(done)
			s.Serve(c)
		}()
		runtime.Gosched()
		s.Close()
		Eventually(done).Should(BeClosed())
	})

	Context("ConfigureTLSConfig", func() {
		It("advertises v1 by default", func() {
			conf := ConfigureTLSConfig(testdata.GetTLSConfig())
			ln, err := quic.ListenAddr("localhost:0", conf, &quic.Config{Versions: []quic.Version{quic.Version1}})
			Expect(err).ToNot(HaveOccurred())
			defer ln.Close()
			c, err := quic.DialAddr(context.Background(), ln.Addr().String(), &tls.Config{InsecureSkipVerify: true, NextProtos: []string{NextProtoH3}}, nil)
			Expect(err).ToNot(HaveOccurred())
			defer c.CloseWithError(0, "")
			Expect(c.ConnectionState().TLS.NegotiatedProtocol).To(Equal(NextProtoH3))
		})

		It("sets the GetConfigForClient callback if no tls.Config is given", func() {
			var receivedConf *tls.Config
			quicListenAddr = func(addr string, tlsConf *tls.Config, _ *quic.Config) (QUICEarlyListener, error) {
				receivedConf = tlsConf
				return nil, errors.New("listen err")
			}
			Expect(s.ListenAndServe()).To(HaveOccurred())
			Expect(receivedConf).ToNot(BeNil())
		})

		It("sets the ALPN for tls.Configs returned by the tls.GetConfigForClient", func() {
			tlsConf := &tls.Config{
				GetConfigForClient: func(ch *tls.ClientHelloInfo) (*tls.Config, error) {
					c := testdata.GetTLSConfig()
					c.NextProtos = []string{"foo", "bar"}
					return c, nil
				},
			}

			ln, err := quic.ListenAddr("localhost:0", ConfigureTLSConfig(tlsConf), &quic.Config{Versions: []quic.Version{quic.Version1}})
			Expect(err).ToNot(HaveOccurred())
			defer ln.Close()
			c, err := quic.DialAddr(context.Background(), ln.Addr().String(), &tls.Config{InsecureSkipVerify: true, NextProtos: []string{NextProtoH3}}, nil)
			Expect(err).ToNot(HaveOccurred())
			defer c.CloseWithError(0, "")
			Expect(c.ConnectionState().TLS.NegotiatedProtocol).To(Equal(NextProtoH3))
		})

		It("works if GetConfigForClient returns a nil tls.Config", func() {
			tlsConf := testdata.GetTLSConfig()
			tlsConf.GetConfigForClient = func(*tls.ClientHelloInfo) (*tls.Config, error) { return nil, nil }

			ln, err := quic.ListenAddr("localhost:0", ConfigureTLSConfig(tlsConf), &quic.Config{Versions: []quic.Version{quic.Version1}})
			Expect(err).ToNot(HaveOccurred())
			defer ln.Close()
			c, err := quic.DialAddr(context.Background(), ln.Addr().String(), &tls.Config{InsecureSkipVerify: true, NextProtos: []string{NextProtoH3}}, nil)
			Expect(err).ToNot(HaveOccurred())
			defer c.CloseWithError(0, "")
			Expect(c.ConnectionState().TLS.NegotiatedProtocol).To(Equal(NextProtoH3))
		})

		It("sets the ALPN for tls.Configs returned by the tls.GetConfigForClient, if it returns a static tls.Config", func() {
			tlsClientConf := testdata.GetTLSConfig()
			tlsClientConf.NextProtos = []string{"foo", "bar"}
			tlsConf := &tls.Config{
				GetConfigForClient: func(ch *tls.ClientHelloInfo) (*tls.Config, error) {
					return tlsClientConf, nil
				},
			}

			ln, err := quic.ListenAddr("localhost:0", ConfigureTLSConfig(tlsConf), &quic.Config{Versions: []quic.Version{quic.Version1}})
			Expect(err).ToNot(HaveOccurred())
			defer ln.Close()
			c, err := quic.DialAddr(context.Background(), ln.Addr().String(), &tls.Config{InsecureSkipVerify: true, NextProtos: []string{NextProtoH3}}, nil)
			Expect(err).ToNot(HaveOccurred())
			defer c.CloseWithError(0, "")
			Expect(c.ConnectionState().TLS.NegotiatedProtocol).To(Equal(NextProtoH3))
			// check that the original config was not modified
			Expect(tlsClientConf.NextProtos).To(Equal([]string{"foo", "bar"}))
		})
	})

	Context("Serve", func() {
		origQuicListen := quicListen

		AfterEach(func() {
			quicListen = origQuicListen
		})

		It("serves a packet conn", func() {
			ln := newMockAddrListener(":443")
			conn := &net.UDPConn{}
			quicListen = func(c net.PacketConn, tlsConf *tls.Config, config *quic.Config) (QUICEarlyListener, error) {
				Expect(c).To(Equal(conn))
				return ln, nil
			}

			s := &Server{
				TLSConfig: &tls.Config{},
			}

			stopAccept := make(chan struct{})
			ln.EXPECT().Accept(gomock.Any()).DoAndReturn(func(context.Context) (quic.EarlyConnection, error) {
				<-stopAccept
				return nil, errors.New("closed")
			})
			ln.EXPECT().Addr() // generate alt-svc headers
			done := make(chan struct{})
			go func() {
				defer GinkgoRecover()
				defer close(done)
				s.Serve(conn)
			}()

			Consistently(done).ShouldNot(BeClosed())
			ln.EXPECT().Close().Do(func() error { close(stopAccept); return nil })
			Expect(s.Close()).To(Succeed())
			Eventually(done).Should(BeClosed())
		})

		It("serves two packet conns", func() {
			ln1 := newMockAddrListener(":443")
			ln2 := newMockAddrListener(":8443")
			lns := make(chan QUICEarlyListener, 2)
			lns <- ln1
			lns <- ln2
			conn1 := &net.UDPConn{}
			conn2 := &net.UDPConn{}
			quicListen = func(c net.PacketConn, tlsConf *tls.Config, config *quic.Config) (QUICEarlyListener, error) {
				return <-lns, nil
			}

			s := &Server{
				TLSConfig: &tls.Config{},
			}

			stopAccept1 := make(chan struct{})
			ln1.EXPECT().Accept(gomock.Any()).DoAndReturn(func(context.Context) (quic.EarlyConnection, error) {
				<-stopAccept1
				return nil, errors.New("closed")
			})
			ln1.EXPECT().Addr() // generate alt-svc headers
			stopAccept2 := make(chan struct{})
			ln2.EXPECT().Accept(gomock.Any()).DoAndReturn(func(context.Context) (quic.EarlyConnection, error) {
				<-stopAccept2
				return nil, errors.New("closed")
			})
			ln2.EXPECT().Addr()

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
			ln1.EXPECT().Close().Do(func() error { close(stopAccept1); return nil })
			ln2.EXPECT().Close().Do(func() error { close(stopAccept2); return nil })
			Expect(s.Close()).To(Succeed())
			Eventually(done1).Should(BeClosed())
			Eventually(done2).Should(BeClosed())
		})
	})

	Context("ServeListener", func() {
		origQuicListen := quicListen

		AfterEach(func() {
			quicListen = origQuicListen
		})

		It("serves a listener", func() {
			var called atomic.Bool
			ln := newMockAddrListener(":443")
			quicListen = func(conn net.PacketConn, tlsConf *tls.Config, config *quic.Config) (QUICEarlyListener, error) {
				called.Store(true)
				return ln, nil
			}

			s := &Server{}

			stopAccept := make(chan struct{})
			ln.EXPECT().Accept(gomock.Any()).DoAndReturn(func(context.Context) (quic.EarlyConnection, error) {
				<-stopAccept
				return nil, errors.New("closed")
			})
			ln.EXPECT().Addr() // generate alt-svc headers
			done := make(chan struct{})
			go func() {
				defer GinkgoRecover()
				defer close(done)
				s.ServeListener(ln)
			}()

			Consistently(called.Load).Should(BeFalse())
			Consistently(done).ShouldNot(BeClosed())
			ln.EXPECT().Close().Do(func() error { close(stopAccept); return nil })
			Expect(s.Close()).To(Succeed())
			Eventually(done).Should(BeClosed())
		})

		It("serves two listeners", func() {
			var called atomic.Bool
			ln1 := newMockAddrListener(":443")
			ln2 := newMockAddrListener(":8443")
			lns := make(chan QUICEarlyListener, 2)
			lns <- ln1
			lns <- ln2
			quicListen = func(c net.PacketConn, tlsConf *tls.Config, config *quic.Config) (QUICEarlyListener, error) {
				called.Store(true)
				return <-lns, nil
			}

			s := &Server{}

			stopAccept1 := make(chan struct{})
			ln1.EXPECT().Accept(gomock.Any()).DoAndReturn(func(context.Context) (quic.EarlyConnection, error) {
				<-stopAccept1
				return nil, errors.New("closed")
			})
			ln1.EXPECT().Addr() // generate alt-svc headers
			stopAccept2 := make(chan struct{})
			ln2.EXPECT().Accept(gomock.Any()).DoAndReturn(func(context.Context) (quic.EarlyConnection, error) {
				<-stopAccept2
				return nil, errors.New("closed")
			})
			ln2.EXPECT().Addr()

			done1 := make(chan struct{})
			go func() {
				defer GinkgoRecover()
				defer close(done1)
				s.ServeListener(ln1)
			}()
			done2 := make(chan struct{})
			go func() {
				defer GinkgoRecover()
				defer close(done2)
				s.ServeListener(ln2)
			}()

			Consistently(called.Load).Should(BeFalse())
			Consistently(done1).ShouldNot(BeClosed())
			Expect(done2).ToNot(BeClosed())
			ln1.EXPECT().Close().Do(func() error { close(stopAccept1); return nil })
			ln2.EXPECT().Close().Do(func() error { close(stopAccept2); return nil })
			Expect(s.Close()).To(Succeed())
			Eventually(done1).Should(BeClosed())
			Eventually(done2).Should(BeClosed())
		})
	})

	Context("ServeQUICConn", func() {
		It("serves a QUIC connection", func() {
			mux := http.NewServeMux()
			mux.HandleFunc("/hello", func(w http.ResponseWriter, _ *http.Request) {
				w.Write([]byte("foobar"))
			})
			s.Handler = mux
			tlsConf := testdata.GetTLSConfig()
			tlsConf.NextProtos = []string{NextProtoH3}
			conn := mockquic.NewMockEarlyConnection(mockCtrl)
			controlStr := mockquic.NewMockStream(mockCtrl)
			controlStr.EXPECT().Write(gomock.Any())
			conn.EXPECT().LocalAddr()
			conn.EXPECT().RemoteAddr()
			conn.EXPECT().Context().Return(context.Background())
			conn.EXPECT().OpenUniStream().Return(controlStr, nil)
			testDone := make(chan struct{})
			conn.EXPECT().AcceptUniStream(gomock.Any()).DoAndReturn(func(context.Context) (quic.ReceiveStream, error) {
				<-testDone
				return nil, errors.New("test done")
			}).MaxTimes(1)
			conn.EXPECT().AcceptStream(gomock.Any()).Return(nil, &quic.ApplicationError{ErrorCode: quic.ApplicationErrorCode(ErrCodeNoError)})
			s.ServeQUICConn(conn)
			close(testDone)
		})
	})

	Context("ListenAndServe", func() {
		BeforeEach(func() {
			s.Addr = "localhost:0"
		})

		AfterEach(func() {
			Expect(s.Close()).To(Succeed())
		})

		It("uses the quic.Config to start the QUIC server", func() {
			conf := &quic.Config{HandshakeIdleTimeout: time.Nanosecond}
			var receivedConf *quic.Config
			quicListenAddr = func(addr string, _ *tls.Config, config *quic.Config) (QUICEarlyListener, error) {
				receivedConf = config
				return nil, errors.New("listen err")
			}
			s.QUICConfig = conf
			Expect(s.ListenAndServe()).To(HaveOccurred())
			Expect(receivedConf).To(Equal(conf))
		})
	})

	It("closes gracefully", func() {
		Expect(s.Shutdown(context.Background())).To(Succeed())
	})

	It("errors when listening fails", func() {
		testErr := errors.New("listen error")
		quicListenAddr = func(addr string, tlsConf *tls.Config, config *quic.Config) (QUICEarlyListener, error) {
			return nil, testErr
		}
		fullpem, privkey := testdata.GetCertificatePaths()
		Expect(ListenAndServeQUIC("", fullpem, privkey, nil)).To(MatchError(testErr))
	})

	It("supports H3_DATAGRAM", func() {
		s.EnableDatagrams = true
		var receivedConf *quic.Config
		quicListenAddr = func(addr string, _ *tls.Config, config *quic.Config) (QUICEarlyListener, error) {
			receivedConf = config
			return nil, errors.New("listen err")
		}
		Expect(s.ListenAndServe()).To(HaveOccurred())
		Expect(receivedConf.EnableDatagrams).To(BeTrue())
	})
})
