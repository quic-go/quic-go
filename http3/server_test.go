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
	"runtime"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
	mockquic "github.com/quic-go/quic-go/internal/mocks/quic"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/testdata"
	"github.com/quic-go/quic-go/internal/utils"
	"github.com/quic-go/quic-go/quicvarint"

	"github.com/golang/mock/gomock"
	"github.com/quic-go/qpack"

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

	BeforeEach(func() {
		s = &Server{
			TLSConfig: testdata.GetTLSConfig(),
			logger:    utils.DefaultLogger,
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
			conn               *mockquic.MockEarlyConnection
			exampleGetRequest  *http.Request
			examplePostRequest *http.Request
		)
		reqContext := context.Background()

		decodeHeader := func(str io.Reader) map[string][]string {
			fields := make(map[string][]string)
			decoder := qpack.NewDecoder(nil)

			frame, err := parseNextFrame(str, nil)
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
			rw := newRequestWriter(utils.DefaultLogger)
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
			conn = mockquic.NewMockEarlyConnection(mockCtrl)
			addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1337}
			conn.EXPECT().RemoteAddr().Return(addr).AnyTimes()
			conn.EXPECT().LocalAddr().AnyTimes()
			conn.EXPECT().ConnectionState().Return(quic.ConnectionState{}).AnyTimes()
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
			str.EXPECT().CancelRead(gomock.Any())

			Expect(s.handleRequest(conn, str, qpackDecoder, nil)).To(Equal(requestError{}))
			var req *http.Request
			Eventually(requestChan).Should(Receive(&req))
			Expect(req.Host).To(Equal("www.example.com"))
			Expect(req.RemoteAddr).To(Equal("127.0.0.1:1337"))
			Expect(req.Context().Value(ServerContextKey)).To(Equal(s))
		})

		It("returns 200 with an empty handler", func() {
			s.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})

			responseBuf := &bytes.Buffer{}
			setRequest(encodeRequest(exampleGetRequest))
			str.EXPECT().Context().Return(reqContext)
			str.EXPECT().Write(gomock.Any()).DoAndReturn(responseBuf.Write).AnyTimes()
			str.EXPECT().CancelRead(gomock.Any())

			serr := s.handleRequest(conn, str, qpackDecoder, nil)
			Expect(serr.err).ToNot(HaveOccurred())
			hfs := decodeHeader(responseBuf)
			Expect(hfs).To(HaveKeyWithValue(":status", []string{"200"}))
		})

		It("handles a aborting handler", func() {
			s.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				panic(http.ErrAbortHandler)
			})

			responseBuf := &bytes.Buffer{}
			setRequest(encodeRequest(exampleGetRequest))
			str.EXPECT().Context().Return(reqContext)
			str.EXPECT().Write(gomock.Any()).DoAndReturn(responseBuf.Write).AnyTimes()
			str.EXPECT().CancelRead(gomock.Any())

			serr := s.handleRequest(conn, str, qpackDecoder, nil)
			Expect(serr.err).ToNot(HaveOccurred())
			Expect(responseBuf.Bytes()).To(HaveLen(0))
		})

		It("handles a panicking handler", func() {
			s.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				panic("foobar")
			})

			responseBuf := &bytes.Buffer{}
			setRequest(encodeRequest(exampleGetRequest))
			str.EXPECT().Context().Return(reqContext)
			str.EXPECT().Write(gomock.Any()).DoAndReturn(responseBuf.Write).AnyTimes()
			str.EXPECT().CancelRead(gomock.Any())

			serr := s.handleRequest(conn, str, qpackDecoder, nil)
			Expect(serr.err).ToNot(HaveOccurred())
			Expect(responseBuf.Bytes()).To(HaveLen(0))
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
				frameTypeChan := make(chan FrameType, 1)
				s.StreamHijacker = func(ft FrameType, c quic.Connection, s quic.Stream, e error) (hijacked bool, err error) {
					Expect(e).ToNot(HaveOccurred())
					frameTypeChan <- ft
					return true, nil
				}

				buf := bytes.NewBuffer(quicvarint.Append(nil, 0x41))
				unknownStr := mockquic.NewMockStream(mockCtrl)
				unknownStr.EXPECT().Read(gomock.Any()).DoAndReturn(buf.Read).AnyTimes()
				conn.EXPECT().AcceptStream(gomock.Any()).Return(unknownStr, nil)
				conn.EXPECT().AcceptStream(gomock.Any()).Return(nil, errors.New("done"))
				conn.EXPECT().AcceptUniStream(gomock.Any()).DoAndReturn(func(context.Context) (quic.ReceiveStream, error) {
					<-testDone
					return nil, errors.New("test done")
				})
				s.handleConn(conn)
				Eventually(frameTypeChan).Should(Receive(BeEquivalentTo(0x41)))
				time.Sleep(scaleDuration(20 * time.Millisecond)) // don't EXPECT any calls to conn.CloseWithError
			})

			It("cancels writing when hijacker didn't hijack a bidirectional stream", func() {
				frameTypeChan := make(chan FrameType, 1)
				s.StreamHijacker = func(ft FrameType, c quic.Connection, s quic.Stream, e error) (hijacked bool, err error) {
					Expect(e).ToNot(HaveOccurred())
					frameTypeChan <- ft
					return false, nil
				}

				buf := bytes.NewBuffer(quicvarint.Append(nil, 0x41))
				unknownStr := mockquic.NewMockStream(mockCtrl)
				unknownStr.EXPECT().Read(gomock.Any()).DoAndReturn(buf.Read).AnyTimes()
				unknownStr.EXPECT().CancelWrite(quic.StreamErrorCode(ErrCodeRequestIncomplete))
				conn.EXPECT().AcceptStream(gomock.Any()).Return(unknownStr, nil)
				conn.EXPECT().AcceptStream(gomock.Any()).Return(nil, errors.New("done"))
				conn.EXPECT().AcceptUniStream(gomock.Any()).DoAndReturn(func(context.Context) (quic.ReceiveStream, error) {
					<-testDone
					return nil, errors.New("test done")
				})
				s.handleConn(conn)
				Eventually(frameTypeChan).Should(Receive(BeEquivalentTo(0x41)))
				time.Sleep(scaleDuration(20 * time.Millisecond)) // don't EXPECT any calls to conn.CloseWithError
			})

			It("cancels writing when hijacker returned error", func() {
				frameTypeChan := make(chan FrameType, 1)
				s.StreamHijacker = func(ft FrameType, c quic.Connection, s quic.Stream, e error) (hijacked bool, err error) {
					Expect(e).ToNot(HaveOccurred())
					frameTypeChan <- ft
					return false, errors.New("error in hijacker")
				}

				buf := bytes.NewBuffer(quicvarint.Append(nil, 0x41))
				unknownStr := mockquic.NewMockStream(mockCtrl)
				unknownStr.EXPECT().Read(gomock.Any()).DoAndReturn(buf.Read).AnyTimes()
				unknownStr.EXPECT().CancelWrite(quic.StreamErrorCode(ErrCodeRequestIncomplete))
				conn.EXPECT().AcceptStream(gomock.Any()).Return(unknownStr, nil)
				conn.EXPECT().AcceptStream(gomock.Any()).Return(nil, errors.New("done"))
				conn.EXPECT().AcceptUniStream(gomock.Any()).DoAndReturn(func(context.Context) (quic.ReceiveStream, error) {
					<-testDone
					return nil, errors.New("test done")
				})
				s.handleConn(conn)
				Eventually(frameTypeChan).Should(Receive(BeEquivalentTo(0x41)))
				time.Sleep(scaleDuration(20 * time.Millisecond)) // don't EXPECT any calls to conn.CloseWithError
			})

			It("handles errors that occur when reading the stream type", func() {
				testErr := errors.New("test error")
				done := make(chan struct{})
				unknownStr := mockquic.NewMockStream(mockCtrl)
				s.StreamHijacker = func(ft FrameType, _ quic.Connection, str quic.Stream, err error) (bool, error) {
					defer close(done)
					Expect(ft).To(BeZero())
					Expect(str).To(Equal(unknownStr))
					Expect(err).To(MatchError(testErr))
					return true, nil
				}

				unknownStr.EXPECT().Read(gomock.Any()).Return(0, testErr).AnyTimes()
				conn.EXPECT().AcceptStream(gomock.Any()).Return(unknownStr, nil)
				conn.EXPECT().AcceptStream(gomock.Any()).Return(nil, errors.New("done"))
				conn.EXPECT().AcceptUniStream(gomock.Any()).DoAndReturn(func(context.Context) (quic.ReceiveStream, error) {
					<-testDone
					return nil, errors.New("test done")
				})
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
				streamTypeChan := make(chan StreamType, 1)
				s.UniStreamHijacker = func(st StreamType, _ quic.Connection, _ quic.ReceiveStream, err error) bool {
					Expect(err).ToNot(HaveOccurred())
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
				s.handleConn(conn)
				Eventually(streamTypeChan).Should(Receive(BeEquivalentTo(0x54)))
				time.Sleep(scaleDuration(20 * time.Millisecond)) // don't EXPECT any calls to conn.CloseWithError
			})

			It("handles errors that occur when reading the stream type", func() {
				testErr := errors.New("test error")
				done := make(chan struct{})
				unknownStr := mockquic.NewMockStream(mockCtrl)
				s.UniStreamHijacker = func(st StreamType, _ quic.Connection, str quic.ReceiveStream, err error) bool {
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
				s.handleConn(conn)
				Eventually(done).Should(BeClosed())
				time.Sleep(scaleDuration(20 * time.Millisecond)) // don't EXPECT any calls to conn.CloseWithError
			})

			It("cancels reading when hijacker didn't hijack an unidirectional stream", func() {
				streamTypeChan := make(chan StreamType, 1)
				s.UniStreamHijacker = func(st StreamType, _ quic.Connection, _ quic.ReceiveStream, err error) bool {
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
				s.handleConn(conn)
				Eventually(streamTypeChan).Should(Receive(BeEquivalentTo(0x54)))
				time.Sleep(scaleDuration(20 * time.Millisecond)) // don't EXPECT any calls to conn.CloseWithError
			})
		})

		Context("control stream handling", func() {
			var conn *mockquic.MockEarlyConnection
			testDone := make(chan struct{})

			BeforeEach(func() {
				conn = mockquic.NewMockEarlyConnection(mockCtrl)
				controlStr := mockquic.NewMockStream(mockCtrl)
				controlStr.EXPECT().Write(gomock.Any())
				conn.EXPECT().OpenUniStream().Return(controlStr, nil)
				conn.EXPECT().AcceptStream(gomock.Any()).Return(nil, errors.New("done"))
				conn.EXPECT().RemoteAddr().Return(&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1337}).AnyTimes()
				conn.EXPECT().LocalAddr().AnyTimes()
			})

			AfterEach(func() { testDone <- struct{}{} })

			It("parses the SETTINGS frame", func() {
				b := quicvarint.Append(nil, streamTypeControlStream)
				b = (&settingsFrame{}).Append(b)
				controlStr := mockquic.NewMockStream(mockCtrl)
				r := bytes.NewReader(b)
				controlStr.EXPECT().Read(gomock.Any()).DoAndReturn(r.Read).AnyTimes()
				conn.EXPECT().AcceptUniStream(gomock.Any()).DoAndReturn(func(context.Context) (quic.ReceiveStream, error) {
					return controlStr, nil
				})
				conn.EXPECT().AcceptUniStream(gomock.Any()).DoAndReturn(func(context.Context) (quic.ReceiveStream, error) {
					<-testDone
					return nil, errors.New("test done")
				})
				s.handleConn(conn)
				time.Sleep(scaleDuration(20 * time.Millisecond)) // don't EXPECT any calls to conn.CloseWithError
			})

			for _, t := range []uint64{streamTypeQPACKEncoderStream, streamTypeQPACKDecoderStream} {
				streamType := t
				name := "encoder"
				if streamType == streamTypeQPACKDecoderStream {
					name = "decoder"
				}

				It(fmt.Sprintf("ignores the QPACK %s streams", name), func() {
					buf := bytes.NewBuffer(quicvarint.Append(nil, streamType))
					str := mockquic.NewMockStream(mockCtrl)
					str.EXPECT().Read(gomock.Any()).DoAndReturn(buf.Read).AnyTimes()

					conn.EXPECT().AcceptUniStream(gomock.Any()).DoAndReturn(func(context.Context) (quic.ReceiveStream, error) {
						return str, nil
					})
					conn.EXPECT().AcceptUniStream(gomock.Any()).DoAndReturn(func(context.Context) (quic.ReceiveStream, error) {
						<-testDone
						return nil, errors.New("test done")
					})
					s.handleConn(conn)
					time.Sleep(scaleDuration(20 * time.Millisecond)) // don't EXPECT any calls to str.CancelRead
				})
			}

			It("reset streams other than the control stream and the QPACK streams", func() {
				buf := bytes.NewBuffer(quicvarint.Append(nil, 0o1337))
				str := mockquic.NewMockStream(mockCtrl)
				str.EXPECT().Read(gomock.Any()).DoAndReturn(buf.Read).AnyTimes()
				done := make(chan struct{})
				str.EXPECT().CancelRead(quic.StreamErrorCode(ErrCodeStreamCreationError)).Do(func(code quic.StreamErrorCode) {
					close(done)
				})

				conn.EXPECT().AcceptUniStream(gomock.Any()).DoAndReturn(func(context.Context) (quic.ReceiveStream, error) {
					return str, nil
				})
				conn.EXPECT().AcceptUniStream(gomock.Any()).DoAndReturn(func(context.Context) (quic.ReceiveStream, error) {
					<-testDone
					return nil, errors.New("test done")
				})
				s.handleConn(conn)
				Eventually(done).Should(BeClosed())
			})

			It("errors when the first frame on the control stream is not a SETTINGS frame", func() {
				b := quicvarint.Append(nil, streamTypeControlStream)
				b = (&dataFrame{}).Append(b)
				controlStr := mockquic.NewMockStream(mockCtrl)
				r := bytes.NewReader(b)
				controlStr.EXPECT().Read(gomock.Any()).DoAndReturn(r.Read).AnyTimes()
				conn.EXPECT().AcceptUniStream(gomock.Any()).DoAndReturn(func(context.Context) (quic.ReceiveStream, error) {
					return controlStr, nil
				})
				conn.EXPECT().AcceptUniStream(gomock.Any()).DoAndReturn(func(context.Context) (quic.ReceiveStream, error) {
					<-testDone
					return nil, errors.New("test done")
				})
				done := make(chan struct{})
				conn.EXPECT().CloseWithError(gomock.Any(), gomock.Any()).Do(func(code quic.ApplicationErrorCode, _ string) {
					defer GinkgoRecover()
					Expect(code).To(BeEquivalentTo(ErrCodeMissingSettings))
					close(done)
				})
				s.handleConn(conn)
				Eventually(done).Should(BeClosed())
			})

			It("errors when parsing the frame on the control stream fails", func() {
				b := quicvarint.Append(nil, streamTypeControlStream)
				b = (&settingsFrame{}).Append(b)
				r := bytes.NewReader(b[:len(b)-1])
				controlStr := mockquic.NewMockStream(mockCtrl)
				controlStr.EXPECT().Read(gomock.Any()).DoAndReturn(r.Read).AnyTimes()
				conn.EXPECT().AcceptUniStream(gomock.Any()).DoAndReturn(func(context.Context) (quic.ReceiveStream, error) {
					return controlStr, nil
				})
				conn.EXPECT().AcceptUniStream(gomock.Any()).DoAndReturn(func(context.Context) (quic.ReceiveStream, error) {
					<-testDone
					return nil, errors.New("test done")
				})
				done := make(chan struct{})
				conn.EXPECT().CloseWithError(gomock.Any(), gomock.Any()).Do(func(code quic.ApplicationErrorCode, _ string) {
					defer GinkgoRecover()
					Expect(code).To(BeEquivalentTo(ErrCodeFrameError))
					close(done)
				})
				s.handleConn(conn)
				Eventually(done).Should(BeClosed())
			})

			It("errors when the client opens a push stream", func() {
				b := quicvarint.Append(nil, streamTypePushStream)
				b = (&dataFrame{}).Append(b)
				r := bytes.NewReader(b)
				controlStr := mockquic.NewMockStream(mockCtrl)
				controlStr.EXPECT().Read(gomock.Any()).DoAndReturn(r.Read).AnyTimes()
				conn.EXPECT().AcceptUniStream(gomock.Any()).DoAndReturn(func(context.Context) (quic.ReceiveStream, error) {
					return controlStr, nil
				})
				conn.EXPECT().AcceptUniStream(gomock.Any()).DoAndReturn(func(context.Context) (quic.ReceiveStream, error) {
					<-testDone
					return nil, errors.New("test done")
				})
				done := make(chan struct{})
				conn.EXPECT().CloseWithError(gomock.Any(), gomock.Any()).Do(func(code quic.ApplicationErrorCode, _ string) {
					defer GinkgoRecover()
					Expect(code).To(BeEquivalentTo(ErrCodeStreamCreationError))
					close(done)
				})
				s.handleConn(conn)
				Eventually(done).Should(BeClosed())
			})

			It("errors when the client advertises datagram support (and we enabled support for it)", func() {
				s.EnableDatagrams = true
				b := quicvarint.Append(nil, streamTypeControlStream)
				b = (&settingsFrame{Datagram: true}).Append(b)
				r := bytes.NewReader(b)
				controlStr := mockquic.NewMockStream(mockCtrl)
				controlStr.EXPECT().Read(gomock.Any()).DoAndReturn(r.Read).AnyTimes()
				conn.EXPECT().AcceptUniStream(gomock.Any()).DoAndReturn(func(context.Context) (quic.ReceiveStream, error) {
					return controlStr, nil
				})
				conn.EXPECT().AcceptUniStream(gomock.Any()).DoAndReturn(func(context.Context) (quic.ReceiveStream, error) {
					<-testDone
					return nil, errors.New("test done")
				})
				conn.EXPECT().ConnectionState().Return(quic.ConnectionState{SupportsDatagrams: false})
				done := make(chan struct{})
				conn.EXPECT().CloseWithError(gomock.Any(), gomock.Any()).Do(func(code quic.ApplicationErrorCode, reason string) {
					defer GinkgoRecover()
					Expect(code).To(BeEquivalentTo(ErrCodeSettingsError))
					Expect(reason).To(Equal("missing QUIC Datagram support"))
					close(done)
				})
				s.handleConn(conn)
				Eventually(done).Should(BeClosed())
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
				str.EXPECT().Context().Return(reqContext)
				str.EXPECT().Write(gomock.Any()).DoAndReturn(responseBuf.Write).AnyTimes()
				str.EXPECT().CancelRead(quic.StreamErrorCode(ErrCodeNoError))
				str.EXPECT().Close().Do(func() { close(done) })

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
					r.Body.(HTTPStreamer).HTTPStream()
					str.Write([]byte("foobar"))
				})

				requestData := encodeRequest(exampleGetRequest)
				b := (&dataFrame{Length: 6}).Append(nil) // add a body
				b = append(b, []byte("foobar")...)
				setRequest(append(requestData, b...))
				str.EXPECT().Context().Return(reqContext)
				str.EXPECT().Write([]byte("foobar")).Return(6, nil)

				s.handleConn(conn)
				Eventually(handlerCalled).Should(BeClosed())
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
				conn.EXPECT().CloseWithError(gomock.Any(), gomock.Any()).Do(func(code quic.ApplicationErrorCode, _ string) {
					Expect(code).To(Equal(quic.ApplicationErrorCode(ErrCodeFrameUnexpected)))
					close(done)
				})
				s.handleConn(conn)
				Eventually(done).Should(BeClosed())
			})

			It("closes the connection when the first frame is not a HEADERS frame", func() {
				handlerCalled := make(chan struct{})
				s.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					close(handlerCalled)
				})

				// use 2*DefaultMaxHeaderBytes here. qpack will compress the requiest,
				// but the request will still end up larger than DefaultMaxHeaderBytes.
				url := bytes.Repeat([]byte{'a'}, http.DefaultMaxHeaderBytes*2)
				req, err := http.NewRequest(http.MethodGet, "https://"+string(url), nil)
				Expect(err).ToNot(HaveOccurred())
				setRequest(encodeRequest(req))
				// str.EXPECT().Context().Return(reqContext)
				str.EXPECT().Write(gomock.Any()).DoAndReturn(func(p []byte) (int, error) {
					return len(p), nil
				}).AnyTimes()
				done := make(chan struct{})
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
			str.EXPECT().Context().Return(reqContext)
			str.EXPECT().Write(gomock.Any()).DoAndReturn(func(p []byte) (int, error) {
				return len(p), nil
			}).AnyTimes()
			str.EXPECT().CancelRead(quic.StreamErrorCode(ErrCodeNoError))

			serr := s.handleRequest(conn, str, qpackDecoder, nil)
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
			str.EXPECT().CancelRead(quic.StreamErrorCode(ErrCodeNoError))

			serr := s.handleRequest(conn, str, qpackDecoder, nil)
			Expect(serr.err).ToNot(HaveOccurred())
			Eventually(handlerCalled).Should(BeClosed())
		})
	})

	Context("setting http headers", func() {
		BeforeEach(func() {
			s.QuicConfig = &quic.Config{Versions: []protocol.VersionNumber{protocol.Version1}}
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
			Expect(s.SetQuicHeaders(hdr)).To(Succeed())
			Expect(hdr).To(expected)
		}

		checkSetHeaderError := func() {
			hdr := http.Header{}
			Expect(s.SetQuicHeaders(hdr)).To(Equal(ErrNoAltSvcPort))
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
			s.QuicConfig.Versions = []quic.VersionNumber{quic.Version1, quic.Version2}
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
			mln := &noPortListener{newMockAddrListener("")}
			mln.EXPECT().Addr()
			ln1 = mln
			s.addListener(&ln1)
			checkSetHeaders(Equal(expected))
			s.removeListener(&ln1)
			checkSetHeaderError()
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
			s.QuicConfig.Versions = []quic.VersionNumber{quic.Version1, quic.Version1}
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
			ln, err := quic.ListenAddr("localhost:0", conf, &quic.Config{Versions: []quic.VersionNumber{quic.Version1}})
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

			ln, err := quic.ListenAddr("localhost:0", ConfigureTLSConfig(tlsConf), &quic.Config{Versions: []quic.VersionNumber{quic.Version1}})
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

			ln, err := quic.ListenAddr("localhost:0", ConfigureTLSConfig(tlsConf), &quic.Config{Versions: []quic.VersionNumber{quic.Version1}})
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

			ln, err := quic.ListenAddr("localhost:0", ConfigureTLSConfig(tlsConf), &quic.Config{Versions: []quic.VersionNumber{quic.Version1}})
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
			ln.EXPECT().Accept(gomock.Any()).DoAndReturn(func(context.Context) (quic.Connection, error) {
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
			ln.EXPECT().Close().Do(func() { close(stopAccept) })
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
			ln1.EXPECT().Accept(gomock.Any()).DoAndReturn(func(context.Context) (quic.Connection, error) {
				<-stopAccept1
				return nil, errors.New("closed")
			})
			ln1.EXPECT().Addr() // generate alt-svc headers
			stopAccept2 := make(chan struct{})
			ln2.EXPECT().Accept(gomock.Any()).DoAndReturn(func(context.Context) (quic.Connection, error) {
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
			ln1.EXPECT().Close().Do(func() { close(stopAccept1) })
			ln2.EXPECT().Close().Do(func() { close(stopAccept2) })
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
			var called int32
			ln := newMockAddrListener(":443")
			quicListen = func(conn net.PacketConn, tlsConf *tls.Config, config *quic.Config) (QUICEarlyListener, error) {
				atomic.StoreInt32(&called, 1)
				return ln, nil
			}

			s := &Server{}

			stopAccept := make(chan struct{})
			ln.EXPECT().Accept(gomock.Any()).DoAndReturn(func(context.Context) (quic.Connection, error) {
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

			Consistently(func() int32 { return atomic.LoadInt32(&called) }).Should(Equal(int32(0)))
			Consistently(done).ShouldNot(BeClosed())
			ln.EXPECT().Close().Do(func() { close(stopAccept) })
			Expect(s.Close()).To(Succeed())
			Eventually(done).Should(BeClosed())
		})

		It("serves two listeners", func() {
			var called int32
			ln1 := newMockAddrListener(":443")
			ln2 := newMockAddrListener(":8443")
			lns := make(chan QUICEarlyListener, 2)
			lns <- ln1
			lns <- ln2
			quicListen = func(c net.PacketConn, tlsConf *tls.Config, config *quic.Config) (QUICEarlyListener, error) {
				atomic.StoreInt32(&called, 1)
				return <-lns, nil
			}

			s := &Server{}

			stopAccept1 := make(chan struct{})
			ln1.EXPECT().Accept(gomock.Any()).DoAndReturn(func(context.Context) (quic.Connection, error) {
				<-stopAccept1
				return nil, errors.New("closed")
			})
			ln1.EXPECT().Addr() // generate alt-svc headers
			stopAccept2 := make(chan struct{})
			ln2.EXPECT().Accept(gomock.Any()).DoAndReturn(func(context.Context) (quic.Connection, error) {
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

			Consistently(func() int32 { return atomic.LoadInt32(&called) }).Should(Equal(int32(0)))
			Consistently(done1).ShouldNot(BeClosed())
			Expect(done2).ToNot(BeClosed())
			ln1.EXPECT().Close().Do(func() { close(stopAccept1) })
			ln2.EXPECT().Close().Do(func() { close(stopAccept2) })
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
			s.QuicConfig = conf
			Expect(s.ListenAndServe()).To(HaveOccurred())
			Expect(receivedConf).To(Equal(conf))
		})
	})

	It("closes gracefully", func() {
		Expect(s.CloseGracefully(0)).To(Succeed())
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
