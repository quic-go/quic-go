package http3

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptrace"
	"net/textproto"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
	mockquic "github.com/quic-go/quic-go/internal/mocks/quic"
	"github.com/quic-go/quic-go/quicvarint"

	"github.com/quic-go/qpack"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"go.uber.org/mock/gomock"
)

func encodeResponse(status int) []byte {
	buf := &bytes.Buffer{}
	rstr := mockquic.NewMockStream(mockCtrl)
	rstr.EXPECT().Write(gomock.Any()).Do(buf.Write).AnyTimes()
	rw := newResponseWriter(newStream(rstr, nil, nil, func(r io.Reader, u uint64) error { return nil }), nil, false, nil)
	if status == http.StatusEarlyHints {
		rw.header.Add("Link", "</style.css>; rel=preload; as=style")
		rw.header.Add("Link", "</script.js>; rel=preload; as=script")
	}
	rw.WriteHeader(status)
	rw.Flush()
	return buf.Bytes()
}

var _ = Describe("Client", func() {
	var handshakeChan <-chan struct{} // a closed chan

	BeforeEach(func() {
		ch := make(chan struct{})
		close(ch)
		handshakeChan = ch
	})

	Context("hijacking bidirectional streams", func() {
		var (
			request              *http.Request
			conn                 *mockquic.MockEarlyConnection
			settingsFrameWritten chan struct{}
		)
		testDone := make(chan struct{})

		BeforeEach(func() {
			testDone = make(chan struct{})
			settingsFrameWritten = make(chan struct{})
			controlStr := mockquic.NewMockStream(mockCtrl)
			controlStr.EXPECT().Write(gomock.Any()).Do(func(b []byte) (int, error) {
				defer GinkgoRecover()
				close(settingsFrameWritten)
				return len(b), nil
			})
			conn = mockquic.NewMockEarlyConnection(mockCtrl)
			conn.EXPECT().OpenUniStream().Return(controlStr, nil)
			conn.EXPECT().HandshakeComplete().Return(handshakeChan)
			conn.EXPECT().OpenStreamSync(gomock.Any()).Return(nil, errors.New("done"))
			conn.EXPECT().AcceptUniStream(gomock.Any()).Return(nil, errors.New("done")).AnyTimes()
			var err error
			request, err = http.NewRequest("GET", "https://quic.clemente.io:1337/file1.dat", nil)
			Expect(err).ToNot(HaveOccurred())
		})

		AfterEach(func() {
			testDone <- struct{}{}
			Eventually(settingsFrameWritten).Should(BeClosed())
		})

		It("hijacks a bidirectional stream of unknown frame type", func() {
			id := quic.ConnectionTracingID(1234)
			frameTypeChan := make(chan FrameType, 1)
			tr := &Transport{
				StreamHijacker: func(ft FrameType, connTracingID quic.ConnectionTracingID, _ quic.Stream, e error) (hijacked bool, err error) {
					Expect(e).ToNot(HaveOccurred())
					Expect(connTracingID).To(Equal(id))
					frameTypeChan <- ft
					return true, nil
				},
			}

			buf := bytes.NewBuffer(quicvarint.Append(nil, 0x41))
			unknownStr := mockquic.NewMockStream(mockCtrl)
			unknownStr.EXPECT().Read(gomock.Any()).DoAndReturn(buf.Read).AnyTimes()
			conn.EXPECT().AcceptStream(gomock.Any()).Return(unknownStr, nil)
			conn.EXPECT().AcceptStream(gomock.Any()).DoAndReturn(func(context.Context) (quic.Stream, error) {
				<-testDone
				return nil, errors.New("test done")
			})
			ctx := context.WithValue(context.Background(), quic.ConnectionTracingKey, id)
			conn.EXPECT().Context().Return(ctx).AnyTimes()
			cc := tr.NewClientConn(conn)
			_, err := cc.RoundTrip(request)
			Expect(err).To(MatchError("done"))
			Eventually(frameTypeChan).Should(Receive(BeEquivalentTo(0x41)))
			time.Sleep(scaleDuration(20 * time.Millisecond)) // don't EXPECT any calls to conn.CloseWithError
		})

		It("closes the connection when hijacker didn't hijack a bidirectional stream", func() {
			frameTypeChan := make(chan FrameType, 1)
			tr := &Transport{
				StreamHijacker: func(ft FrameType, _ quic.ConnectionTracingID, _ quic.Stream, e error) (hijacked bool, err error) {
					Expect(e).ToNot(HaveOccurred())
					frameTypeChan <- ft
					return false, nil
				},
			}

			buf := bytes.NewBuffer(quicvarint.Append(nil, 0x41))
			unknownStr := mockquic.NewMockStream(mockCtrl)
			unknownStr.EXPECT().Read(gomock.Any()).DoAndReturn(buf.Read).AnyTimes()
			conn.EXPECT().AcceptStream(gomock.Any()).Return(unknownStr, nil)
			conn.EXPECT().AcceptStream(gomock.Any()).DoAndReturn(func(context.Context) (quic.Stream, error) {
				<-testDone
				return nil, errors.New("test done")
			})
			ctx := context.WithValue(context.Background(), quic.ConnectionTracingKey, quic.ConnectionTracingID(1234))
			conn.EXPECT().Context().Return(ctx).AnyTimes()
			conn.EXPECT().CloseWithError(quic.ApplicationErrorCode(ErrCodeFrameUnexpected), gomock.Any()).Return(nil).AnyTimes()
			cc := tr.NewClientConn(conn)
			_, err := cc.RoundTrip(request)
			Expect(err).To(MatchError("done"))
			Eventually(frameTypeChan).Should(Receive(BeEquivalentTo(0x41)))
		})

		It("closes the connection when hijacker returned error", func() {
			frameTypeChan := make(chan FrameType, 1)
			tr := &Transport{
				StreamHijacker: func(ft FrameType, _ quic.ConnectionTracingID, _ quic.Stream, e error) (hijacked bool, err error) {
					Expect(e).ToNot(HaveOccurred())
					frameTypeChan <- ft
					return false, errors.New("error in hijacker")
				},
			}

			buf := bytes.NewBuffer(quicvarint.Append(nil, 0x41))
			unknownStr := mockquic.NewMockStream(mockCtrl)
			unknownStr.EXPECT().Read(gomock.Any()).DoAndReturn(buf.Read).AnyTimes()
			conn.EXPECT().AcceptStream(gomock.Any()).Return(unknownStr, nil)
			conn.EXPECT().AcceptStream(gomock.Any()).DoAndReturn(func(context.Context) (quic.Stream, error) {
				<-testDone
				return nil, errors.New("test done")
			})
			ctx := context.WithValue(context.Background(), quic.ConnectionTracingKey, quic.ConnectionTracingID(1234))
			conn.EXPECT().Context().Return(ctx).AnyTimes()
			conn.EXPECT().CloseWithError(quic.ApplicationErrorCode(ErrCodeFrameUnexpected), gomock.Any()).Return(nil).AnyTimes()
			cc := tr.NewClientConn(conn)
			_, err := cc.RoundTrip(request)
			Expect(err).To(MatchError("done"))
			Eventually(frameTypeChan).Should(Receive(BeEquivalentTo(0x41)))
		})

		It("handles errors that occur when reading the frame type", func() {
			testErr := errors.New("test error")
			unknownStr := mockquic.NewMockStream(mockCtrl)
			done := make(chan struct{})
			tr := &Transport{
				StreamHijacker: func(ft FrameType, _ quic.ConnectionTracingID, str quic.Stream, e error) (hijacked bool, err error) {
					defer close(done)
					Expect(e).To(MatchError(testErr))
					Expect(ft).To(BeZero())
					Expect(str).To(Equal(unknownStr))
					return false, nil
				},
			}

			unknownStr.EXPECT().Read(gomock.Any()).Return(0, testErr).AnyTimes()
			conn.EXPECT().AcceptStream(gomock.Any()).Return(unknownStr, nil)
			conn.EXPECT().AcceptStream(gomock.Any()).DoAndReturn(func(context.Context) (quic.Stream, error) {
				<-testDone
				return nil, errors.New("test done")
			})
			ctx := context.WithValue(context.Background(), quic.ConnectionTracingKey, quic.ConnectionTracingID(1234))
			conn.EXPECT().Context().Return(ctx).AnyTimes()
			conn.EXPECT().CloseWithError(quic.ApplicationErrorCode(ErrCodeFrameUnexpected), gomock.Any()).Return(nil).AnyTimes()
			cc := tr.NewClientConn(conn)
			_, err := cc.RoundTrip(request)
			Expect(err).To(MatchError("done"))
			Eventually(done).Should(BeClosed())
			time.Sleep(scaleDuration(20 * time.Millisecond)) // don't EXPECT any calls to conn.CloseWithError
		})
	})

	Context("hijacking unidirectional streams", func() {
		var (
			req                  *http.Request
			conn                 *mockquic.MockEarlyConnection
			settingsFrameWritten chan struct{}
		)
		testDone := make(chan struct{})

		BeforeEach(func() {
			testDone = make(chan struct{})
			settingsFrameWritten = make(chan struct{})
			controlStr := mockquic.NewMockStream(mockCtrl)
			controlStr.EXPECT().Write(gomock.Any()).Do(func(b []byte) (int, error) {
				defer GinkgoRecover()
				close(settingsFrameWritten)
				return len(b), nil
			})
			conn = mockquic.NewMockEarlyConnection(mockCtrl)
			conn.EXPECT().OpenUniStream().Return(controlStr, nil)
			conn.EXPECT().HandshakeComplete().Return(handshakeChan)
			conn.EXPECT().OpenStreamSync(gomock.Any()).Return(nil, errors.New("done"))
			var err error
			req, err = http.NewRequest("GET", "https://quic.clemente.io:1337/file1.dat", nil)
			Expect(err).ToNot(HaveOccurred())
		})

		AfterEach(func() {
			testDone <- struct{}{}
			Eventually(settingsFrameWritten).Should(BeClosed())
		})

		It("hijacks an unidirectional stream of unknown stream type", func() {
			id := quic.ConnectionTracingID(100)
			streamTypeChan := make(chan StreamType, 1)
			tr := &Transport{
				UniStreamHijacker: func(st StreamType, connTracingID quic.ConnectionTracingID, _ quic.ReceiveStream, err error) bool {
					Expect(connTracingID).To(Equal(id))
					Expect(err).ToNot(HaveOccurred())
					streamTypeChan <- st
					return true
				},
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
			cc := tr.NewClientConn(conn)
			_, err := cc.RoundTrip(req)
			Expect(err).To(MatchError("done"))
			Eventually(streamTypeChan).Should(Receive(BeEquivalentTo(0x54)))
			time.Sleep(scaleDuration(20 * time.Millisecond)) // don't EXPECT any calls to conn.CloseWithError
		})

		It("handles errors that occur when reading the stream type", func() {
			testErr := errors.New("test error")
			done := make(chan struct{})
			unknownStr := mockquic.NewMockStream(mockCtrl)
			tr := &Transport{
				UniStreamHijacker: func(st StreamType, _ quic.ConnectionTracingID, str quic.ReceiveStream, err error) bool {
					defer close(done)
					Expect(st).To(BeZero())
					Expect(str).To(Equal(unknownStr))
					Expect(err).To(MatchError(testErr))
					return true
				},
			}
			unknownStr.EXPECT().Read(gomock.Any()).Return(0, testErr)
			conn.EXPECT().AcceptUniStream(gomock.Any()).Return(unknownStr, nil)
			conn.EXPECT().AcceptUniStream(gomock.Any()).DoAndReturn(func(context.Context) (quic.ReceiveStream, error) {
				<-testDone
				return nil, errors.New("test done")
			})
			ctx := context.WithValue(context.Background(), quic.ConnectionTracingKey, quic.ConnectionTracingID(1234))
			conn.EXPECT().Context().Return(ctx).AnyTimes()
			cc := tr.NewClientConn(conn)
			_, err := cc.RoundTrip(req)
			Expect(err).To(MatchError("done"))
			Eventually(done).Should(BeClosed())
			time.Sleep(scaleDuration(20 * time.Millisecond)) // don't EXPECT any calls to conn.CloseWithError
		})

		It("cancels reading when hijacker didn't hijack an unidirectional stream", func() {
			streamTypeChan := make(chan StreamType, 1)
			tr := &Transport{
				UniStreamHijacker: func(st StreamType, _ quic.ConnectionTracingID, _ quic.ReceiveStream, err error) bool {
					Expect(err).ToNot(HaveOccurred())
					streamTypeChan <- st
					return false
				},
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
			cc := tr.NewClientConn(conn)
			_, err := cc.RoundTrip(req)
			Expect(err).To(MatchError("done"))
			Eventually(streamTypeChan).Should(Receive(BeEquivalentTo(0x54)))
			time.Sleep(scaleDuration(20 * time.Millisecond)) // don't EXPECT any calls to conn.CloseWithError
		})
	})

	Context("SETTINGS handling", func() {
		sendSettings := func() {
			settingsFrameWritten := make(chan struct{})
			controlStr := mockquic.NewMockStream(mockCtrl)
			var buf bytes.Buffer
			controlStr.EXPECT().Write(gomock.Any()).Do(func(b []byte) (int, error) {
				defer GinkgoRecover()
				buf.Write(b)
				close(settingsFrameWritten)
				return len(b), nil
			})
			conn := mockquic.NewMockEarlyConnection(mockCtrl)
			conn.EXPECT().Context().Return(context.Background())
			conn.EXPECT().OpenUniStream().Return(controlStr, nil)
			conn.EXPECT().OpenStreamSync(gomock.Any()).DoAndReturn(func(context.Context) (quic.Stream, error) {
				<-settingsFrameWritten
				return nil, errors.New("test done")
			})
			conn.EXPECT().AcceptUniStream(gomock.Any()).DoAndReturn(func(context.Context) (quic.ReceiveStream, error) {
				<-settingsFrameWritten
				return nil, errors.New("test done")
			}).AnyTimes()
			conn.EXPECT().HandshakeComplete().Return(handshakeChan)
			tr := &Transport{
				EnableDatagrams: true,
			}
			cc := tr.NewClientConn(conn)
			req, err := http.NewRequest(http.MethodGet, "https://quic-go.net", nil)
			Expect(err).ToNot(HaveOccurred())
			_, err = cc.RoundTrip(req)
			Expect(err).To(MatchError("test done"))
			t, err := quicvarint.Read(&buf)
			Expect(err).ToNot(HaveOccurred())
			Expect(t).To(BeEquivalentTo(streamTypeControlStream))
			settings, err := parseSettingsFrame(&buf, uint64(buf.Len()))
			Expect(err).ToNot(HaveOccurred())
			Expect(settings.Datagram).To(BeTrue())
		}

		It("receives SETTINGS", func() {
			sendSettings()
			done := make(chan struct{})
			conn := mockquic.NewMockEarlyConnection(mockCtrl)
			conn.EXPECT().OpenUniStream().DoAndReturn(func() (quic.SendStream, error) {
				<-done
				return nil, errors.New("test done")
			}).MaxTimes(1)
			conn.EXPECT().Context().Return(context.Background())
			b := quicvarint.Append(nil, streamTypeControlStream)
			b = (&settingsFrame{ExtendedConnect: true}).Append(b)
			r := bytes.NewReader(b)
			controlStr := mockquic.NewMockStream(mockCtrl)
			controlStr.EXPECT().Read(gomock.Any()).DoAndReturn(r.Read).AnyTimes()
			conn.EXPECT().AcceptUniStream(gomock.Any()).Return(controlStr, nil)
			conn.EXPECT().AcceptUniStream(gomock.Any()).DoAndReturn(func(context.Context) (quic.ReceiveStream, error) {
				<-done
				return nil, errors.New("test done")
			})

			tr := &Transport{}
			cc := tr.NewClientConn(conn)
			Eventually(cc.ReceivedSettings()).Should(BeClosed())
			settings := cc.Settings()
			Expect(settings.EnableExtendedConnect).To(BeTrue())
			// test shutdown
			conn.EXPECT().CloseWithError(gomock.Any(), gomock.Any()).MaxTimes(1)
			close(done)
		})

		It("checks the server's SETTINGS before sending an Extended CONNECT request", func() {
			sendSettings()
			done := make(chan struct{})
			var wg sync.WaitGroup
			wg.Add(2)
			conn := mockquic.NewMockEarlyConnection(mockCtrl)
			conn.EXPECT().OpenUniStream().DoAndReturn(func() (quic.SendStream, error) {
				<-done
				wg.Done()
				return nil, errors.New("test done")
			}).MaxTimes(1)
			conn.EXPECT().Context().Return(context.Background())
			b := quicvarint.Append(nil, streamTypeControlStream)
			b = (&settingsFrame{ExtendedConnect: true}).Append(b)
			r := bytes.NewReader(b)
			controlStr := mockquic.NewMockStream(mockCtrl)
			controlStr.EXPECT().Read(gomock.Any()).DoAndReturn(r.Read).AnyTimes()
			conn.EXPECT().AcceptUniStream(gomock.Any()).Return(controlStr, nil)
			conn.EXPECT().AcceptUniStream(gomock.Any()).DoAndReturn(func(context.Context) (quic.ReceiveStream, error) {
				<-done
				wg.Done()
				return nil, errors.New("test done")
			})
			conn.EXPECT().HandshakeComplete().Return(handshakeChan)
			conn.EXPECT().Context().Return(context.Background())
			conn.EXPECT().OpenStreamSync(gomock.Any()).Return(nil, errors.New("test error"))

			tr := &Transport{}
			cc := tr.NewClientConn(conn)
			_, err := cc.RoundTrip(&http.Request{
				Method: http.MethodConnect,
				Proto:  "connect",
				Host:   "localhost",
			})
			Expect(err).To(MatchError("test error"))

			// test shutdown
			conn.EXPECT().CloseWithError(gomock.Any(), gomock.Any()).MaxTimes(1)
			close(done)
			wg.Wait()
		})

		It("rejects Extended CONNECT requests if the server doesn't enable it", func() {
			sendSettings()
			done := make(chan struct{})
			var wg sync.WaitGroup
			wg.Add(2)
			conn := mockquic.NewMockEarlyConnection(mockCtrl)
			conn.EXPECT().Context().Return(context.Background())
			conn.EXPECT().OpenUniStream().DoAndReturn(func() (quic.SendStream, error) {
				<-done
				wg.Done()
				return nil, errors.New("test done")
			}).MaxTimes(1)
			b := quicvarint.Append(nil, streamTypeControlStream)
			b = (&settingsFrame{}).Append(b)
			r := bytes.NewReader(b)
			controlStr := mockquic.NewMockStream(mockCtrl)
			controlStr.EXPECT().Read(gomock.Any()).DoAndReturn(r.Read).AnyTimes()
			conn.EXPECT().AcceptUniStream(gomock.Any()).Return(controlStr, nil)
			conn.EXPECT().AcceptUniStream(gomock.Any()).DoAndReturn(func(context.Context) (quic.ReceiveStream, error) {
				<-done
				wg.Done()
				return nil, errors.New("test done")
			})
			conn.EXPECT().HandshakeComplete().Return(handshakeChan)
			conn.EXPECT().Context().Return(context.Background())

			tr := &Transport{}
			cc := tr.NewClientConn(conn)
			_, err := cc.RoundTrip(&http.Request{
				Method: http.MethodConnect,
				Proto:  "connect",
				Host:   "localhost",
			})
			Expect(err).To(MatchError("http3: server didn't enable Extended CONNECT"))

			// test shutdown
			conn.EXPECT().CloseWithError(gomock.Any(), gomock.Any()).MaxTimes(1)
			close(done)
			wg.Wait()
		})
	})

	Context("Doing requests", func() {
		var (
			req                  *http.Request
			str                  *mockquic.MockStream
			conn                 *mockquic.MockEarlyConnection
			settingsFrameWritten chan struct{}
		)
		testDone := make(chan struct{})

		decodeHeader := func(str io.Reader) map[string]string {
			fields := make(map[string]string)
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
				fields[p.Name] = p.Value
			}
			return fields
		}

		BeforeEach(func() {
			settingsFrameWritten = make(chan struct{})
			controlStr := mockquic.NewMockStream(mockCtrl)
			controlStr.EXPECT().Write(gomock.Any()).Do(func(b []byte) (int, error) {
				defer GinkgoRecover()
				r := bytes.NewReader(b)
				streamType, err := quicvarint.Read(r)
				Expect(err).ToNot(HaveOccurred())
				Expect(streamType).To(BeEquivalentTo(streamTypeControlStream))
				close(settingsFrameWritten)
				return len(b), nil
			}) // SETTINGS frame
			str = mockquic.NewMockStream(mockCtrl)
			str.EXPECT().Context().Return(context.Background()).AnyTimes()
			str.EXPECT().StreamID().AnyTimes()
			conn = mockquic.NewMockEarlyConnection(mockCtrl)
			conn.EXPECT().Context().Return(context.Background())
			conn.EXPECT().OpenUniStream().Return(controlStr, nil)
			conn.EXPECT().AcceptUniStream(gomock.Any()).DoAndReturn(func(context.Context) (quic.ReceiveStream, error) {
				<-testDone
				return nil, errors.New("test done")
			})
			var err error
			req, err = http.NewRequest("GET", "https://quic.clemente.io:1337/file1.dat", nil)
			Expect(err).ToNot(HaveOccurred())
		})

		AfterEach(func() {
			testDone <- struct{}{}
			Eventually(settingsFrameWritten).Should(BeClosed())
		})

		It("errors if it can't open a request stream", func() {
			testErr := errors.New("stream open error")
			conn.EXPECT().OpenStreamSync(context.Background()).Return(nil, testErr)
			conn.EXPECT().CloseWithError(gomock.Any(), gomock.Any()).MaxTimes(1)
			conn.EXPECT().HandshakeComplete().Return(handshakeChan)
			tr := &Transport{}
			cc := tr.NewClientConn(conn)
			_, err := cc.RoundTrip(req)
			Expect(err).To(MatchError(testErr))
		})

		DescribeTable(
			"performs a 0-RTT request",
			func(method, serialized string) {
				testErr := errors.New("stream open error")
				req.Method = method
				// don't EXPECT any calls to HandshakeComplete()
				conn.EXPECT().OpenStreamSync(context.Background()).Return(str, nil)
				buf := &bytes.Buffer{}
				str.EXPECT().Write(gomock.Any()).DoAndReturn(buf.Write).AnyTimes()
				str.EXPECT().Close()
				str.EXPECT().CancelWrite(gomock.Any())
				str.EXPECT().CancelRead(gomock.Any())
				str.EXPECT().Read(gomock.Any()).DoAndReturn(func([]byte) (int, error) {
					return 0, testErr
				})
				tr := &Transport{}
				cc := tr.NewClientConn(conn)
				_, err := cc.RoundTrip(req)
				Expect(err).To(MatchError(testErr))
				Expect(decodeHeader(buf)).To(HaveKeyWithValue(":method", serialized))
				// make sure the request wasn't modified
				Expect(req.Method).To(Equal(method))
			},
			Entry("GET", MethodGet0RTT, http.MethodGet),
			Entry("HEAD", MethodHead0RTT, http.MethodHead),
		)

		It("returns a response", func() {
			rspBuf := bytes.NewBuffer(encodeResponse(418))
			gomock.InOrder(
				conn.EXPECT().HandshakeComplete().Return(handshakeChan),
				conn.EXPECT().OpenStreamSync(context.Background()).Return(str, nil),
				conn.EXPECT().ConnectionState().Return(quic.ConnectionState{}),
			)
			str.EXPECT().Write(gomock.Any()).AnyTimes().DoAndReturn(func(p []byte) (int, error) { return len(p), nil })
			str.EXPECT().Close()
			str.EXPECT().Read(gomock.Any()).DoAndReturn(rspBuf.Read).AnyTimes()
			tr := &Transport{}
			cc := tr.NewClientConn(conn)
			rsp, err := cc.RoundTrip(req)
			Expect(err).ToNot(HaveOccurred())
			Expect(rsp.Proto).To(Equal("HTTP/3.0"))
			Expect(rsp.ProtoMajor).To(Equal(3))
			Expect(rsp.StatusCode).To(Equal(418))
			Expect(rsp.Request).ToNot(BeNil())
		})

		It("returns a response with trailers", func() {
			rspBuf := bytes.NewBuffer(encodeResponse(418))

			trailerBuf := &bytes.Buffer{}
			enc := qpack.NewEncoder(trailerBuf)
			Expect(enc.WriteField(qpack.HeaderField{Name: "This-Is-A-Trailer", Value: "0"})).To(Succeed())
			Expect(enc.Close()).To(Succeed())
			b := (&headersFrame{Length: uint64(trailerBuf.Len())}).Append(nil)
			b = append(b, trailerBuf.Bytes()...)
			rspBuf.Write(b)

			gomock.InOrder(
				conn.EXPECT().HandshakeComplete().Return(handshakeChan),
				conn.EXPECT().OpenStreamSync(context.Background()).Return(str, nil),
				conn.EXPECT().ConnectionState().Return(quic.ConnectionState{}),
			)
			str.EXPECT().Write(gomock.Any()).AnyTimes().DoAndReturn(func(p []byte) (int, error) { return len(p), nil })
			str.EXPECT().Close()
			str.EXPECT().Read(gomock.Any()).DoAndReturn(rspBuf.Read).AnyTimes()
			tr := &Transport{}
			cc := tr.NewClientConn(conn)
			rsp, err := cc.RoundTrip(req)
			Expect(err).ToNot(HaveOccurred())
			_, err = io.ReadAll(rsp.Body)
			Expect(err).ToNot(HaveOccurred())
			Expect(rsp.Trailer).To(Equal(http.Header{"This-Is-A-Trailer": []string{"0"}}))
			Expect(rsp.Proto).To(Equal("HTTP/3.0"))
			Expect(rsp.ProtoMajor).To(Equal(3))
			Expect(rsp.StatusCode).To(Equal(418))
			Expect(rsp.Request).ToNot(BeNil())
		})

		It("errors on invalid HEADERS frames", func() {
			rspBuf := bytes.NewBuffer(encodeResponse(418))

			b := (&headersFrame{Length: 10}).Append(nil)
			b = append(b, []byte("invalid headers frame")...)
			rspBuf.Write(b)

			gomock.InOrder(
				conn.EXPECT().HandshakeComplete().Return(handshakeChan),
				conn.EXPECT().OpenStreamSync(context.Background()).Return(str, nil),
				conn.EXPECT().ConnectionState().Return(quic.ConnectionState{}),
			)
			str.EXPECT().Write(gomock.Any()).AnyTimes().DoAndReturn(func(p []byte) (int, error) { return len(p), nil })
			str.EXPECT().Close()
			str.EXPECT().Read(gomock.Any()).DoAndReturn(rspBuf.Read).AnyTimes()
			tr := &Transport{}
			cc := tr.NewClientConn(conn)
			rsp, err := cc.RoundTrip(req)
			Expect(err).ToNot(HaveOccurred())
			_, err = io.ReadAll(rsp.Body)
			Expect(err).To(HaveOccurred())
		})

		It("returns an error if trailers are sent twice", func() {
			rspBuf := bytes.NewBuffer(encodeResponse(418))

			{
				trailerBuf := &bytes.Buffer{}
				enc := qpack.NewEncoder(trailerBuf)
				Expect(enc.WriteField(qpack.HeaderField{Name: "This-Is-A-Trailer", Value: "0"})).To(Succeed())
				Expect(enc.Close()).To(Succeed())
				b := (&headersFrame{Length: uint64(trailerBuf.Len())}).Append(nil)
				b = append(b, trailerBuf.Bytes()...)
				rspBuf.Write(b)
			}

			{
				trailerBuf := &bytes.Buffer{}
				enc := qpack.NewEncoder(trailerBuf)
				Expect(enc.WriteField(qpack.HeaderField{Name: "This-Is-A-Trailer", Value: "1"})).To(Succeed())
				Expect(enc.Close()).To(Succeed())
				b := (&headersFrame{Length: uint64(trailerBuf.Len())}).Append(nil)
				b = append(b, trailerBuf.Bytes()...)
				rspBuf.Write(b)
			}

			gomock.InOrder(
				conn.EXPECT().HandshakeComplete().Return(handshakeChan),
				conn.EXPECT().OpenStreamSync(context.Background()).Return(str, nil),
				conn.EXPECT().ConnectionState().Return(quic.ConnectionState{}),
			)
			str.EXPECT().Write(gomock.Any()).AnyTimes().DoAndReturn(func(p []byte) (int, error) { return len(p), nil })
			str.EXPECT().Close()
			str.EXPECT().Read(gomock.Any()).DoAndReturn(rspBuf.Read).AnyTimes()
			tr := &Transport{}
			cc := tr.NewClientConn(conn)
			rsp, err := cc.RoundTrip(req)
			Expect(err).ToNot(HaveOccurred())
			_, err = io.ReadAll(rsp.Body)
			Expect(err).To(MatchError(errors.New("additional HEADERS frame received after trailers")))
			Expect(rsp.Trailer).To(Equal(http.Header{"This-Is-A-Trailer": []string{"0"}}))
			Expect(rsp.Proto).To(Equal("HTTP/3.0"))
			Expect(rsp.ProtoMajor).To(Equal(3))
			Expect(rsp.StatusCode).To(Equal(418))
			Expect(rsp.Request).ToNot(BeNil())
		})

		It("returns an error if body frame is received after trailers", func() {
			rspBuf := bytes.NewBuffer(encodeResponse(418))

			{
				trailerBuf := &bytes.Buffer{}
				enc := qpack.NewEncoder(trailerBuf)
				Expect(enc.WriteField(qpack.HeaderField{Name: "This-Is-A-Trailer", Value: "0"})).To(Succeed())
				Expect(enc.Close()).To(Succeed())
				b := (&headersFrame{Length: uint64(trailerBuf.Len())}).Append(nil)
				b = append(b, trailerBuf.Bytes()...)
				rspBuf.Write(b)
			}

			{
				dataBuf := &bytes.Buffer{}
				dataBuf.Write([]byte("test body please ignore"))
				b := (&dataFrame{Length: uint64(dataBuf.Len())}).Append(nil)
				b = append(b, dataBuf.Bytes()...)
				rspBuf.Write(b)
			}

			gomock.InOrder(
				conn.EXPECT().HandshakeComplete().Return(handshakeChan),
				conn.EXPECT().OpenStreamSync(context.Background()).Return(str, nil),
				conn.EXPECT().ConnectionState().Return(quic.ConnectionState{}),
			)
			str.EXPECT().Write(gomock.Any()).AnyTimes().DoAndReturn(func(p []byte) (int, error) { return len(p), nil })
			str.EXPECT().Close()
			str.EXPECT().Read(gomock.Any()).DoAndReturn(rspBuf.Read).AnyTimes()
			tr := &Transport{}
			cc := tr.NewClientConn(conn)
			rsp, err := cc.RoundTrip(req)
			Expect(err).ToNot(HaveOccurred())
			_, err = io.ReadAll(rsp.Body)
			Expect(err).To(MatchError(errors.New("DATA frame received after trailers")))
			Expect(rsp.Trailer).To(Equal(http.Header{"This-Is-A-Trailer": []string{"0"}}))
			Expect(rsp.Proto).To(Equal("HTTP/3.0"))
			Expect(rsp.ProtoMajor).To(Equal(3))
			Expect(rsp.StatusCode).To(Equal(418))
			Expect(rsp.Request).ToNot(BeNil())
		})

		Context("requests containing a Body", func() {
			var strBuf *bytes.Buffer

			BeforeEach(func() {
				strBuf = &bytes.Buffer{}
				gomock.InOrder(
					conn.EXPECT().HandshakeComplete().Return(handshakeChan),
					conn.EXPECT().OpenStreamSync(context.Background()).Return(str, nil),
				)
				body := &mockBody{}
				body.SetData([]byte("request body"))
				var err error
				req, err = http.NewRequest("POST", "https://quic.clemente.io:1337/upload", body)
				Expect(err).ToNot(HaveOccurred())
				str.EXPECT().Write(gomock.Any()).DoAndReturn(strBuf.Write).AnyTimes()
			})

			It("sends a request", func() {
				done := make(chan struct{})
				gomock.InOrder(
					str.EXPECT().Close().Do(func() error { close(done); return nil }),
					// when reading the response errors
					str.EXPECT().CancelRead(gomock.Any()).MaxTimes(1),
					str.EXPECT().CancelWrite(gomock.Any()).MaxTimes(1),
				)
				// the response body is sent asynchronously, while already reading the response
				testErr := errors.New("test done")
				str.EXPECT().Read(gomock.Any()).DoAndReturn(func([]byte) (int, error) {
					<-done
					return 0, testErr
				})
				tr := &Transport{}
				cc := tr.NewClientConn(conn)
				_, err := cc.RoundTrip(req)
				Expect(err).To(MatchError(testErr))
				hfs := decodeHeader(strBuf)
				Expect(hfs).To(HaveKeyWithValue(":method", "POST"))
				Expect(hfs).To(HaveKeyWithValue(":path", "/upload"))
			})

			It("doesn't send more bytes than allowed by http.Request.ContentLength", func() {
				req.ContentLength = 7
				var once sync.Once
				done := make(chan struct{})
				str.EXPECT().CancelRead(gomock.Any())
				gomock.InOrder(
					str.EXPECT().CancelWrite(gomock.Any()).Do(func(c quic.StreamErrorCode) {
						once.Do(func() {
							Expect(c).To(Equal(quic.StreamErrorCode(ErrCodeRequestCanceled)))
							close(done)
						})
					}).AnyTimes(),
					str.EXPECT().Close().MaxTimes(1),
					str.EXPECT().CancelWrite(gomock.Any()).AnyTimes(),
				)
				str.EXPECT().Read(gomock.Any()).DoAndReturn(func([]byte) (int, error) {
					<-done
					return 0, errors.New("done")
				})
				tr := &Transport{}
				cc := tr.NewClientConn(conn)
				_, err := cc.RoundTrip(req)
				Expect(err).To(HaveOccurred())
				Expect(strBuf.String()).To(ContainSubstring("request"))
				Expect(strBuf.String()).ToNot(ContainSubstring("request body"))
			})

			It("returns the error that occurred when reading the body", func() {
				req.Body.(*mockBody).readErr = errors.New("testErr")
				done := make(chan struct{})
				str.EXPECT().CancelRead(gomock.Any())
				gomock.InOrder(
					str.EXPECT().CancelWrite(quic.StreamErrorCode(ErrCodeRequestCanceled)).Do(func(quic.StreamErrorCode) {
						close(done)
					}),
					str.EXPECT().CancelWrite(gomock.Any()),
				)

				// the response body is sent asynchronously, while already reading the response
				testErr := errors.New("test done")
				str.EXPECT().Read(gomock.Any()).DoAndReturn(func([]byte) (int, error) {
					<-done
					return 0, testErr
				})
				closed := make(chan struct{})
				str.EXPECT().Close().Do(func() error { close(closed); return nil })
				tr := &Transport{}
				cc := tr.NewClientConn(conn)
				_, err := cc.RoundTrip(req)
				Expect(err).To(MatchError(testErr))
				Eventually(closed).Should(BeClosed())
			})

			It("closes the connection when the first frame is not a HEADERS frame", func() {
				b := (&dataFrame{Length: 0x42}).Append(nil)
				conn.EXPECT().CloseWithError(quic.ApplicationErrorCode(ErrCodeFrameUnexpected), gomock.Any())
				closed := make(chan struct{})
				r := bytes.NewReader(b)
				str.EXPECT().Close().Do(func() error { close(closed); return nil })
				str.EXPECT().Read(gomock.Any()).DoAndReturn(r.Read).AnyTimes()
				tr := &Transport{}
				cc := tr.NewClientConn(conn)
				_, err := cc.RoundTrip(req)
				Expect(err).To(MatchError("http3: expected first frame to be a HEADERS frame"))
				Eventually(closed).Should(BeClosed())
			})

			It("cancels the stream when parsing the headers fails", func() {
				headerBuf := &bytes.Buffer{}
				enc := qpack.NewEncoder(headerBuf)
				Expect(enc.WriteField(qpack.HeaderField{Name: ":method", Value: "GET"})).To(Succeed()) // not a valid response pseudo header
				Expect(enc.Close()).To(Succeed())
				b := (&headersFrame{Length: uint64(headerBuf.Len())}).Append(nil)
				b = append(b, headerBuf.Bytes()...)

				r := bytes.NewReader(b)
				str.EXPECT().CancelRead(quic.StreamErrorCode(ErrCodeMessageError))
				str.EXPECT().CancelWrite(quic.StreamErrorCode(ErrCodeMessageError))
				closed := make(chan struct{})
				str.EXPECT().Close().Do(func() error { close(closed); return nil })
				str.EXPECT().Read(gomock.Any()).DoAndReturn(r.Read).AnyTimes()
				tr := &Transport{}
				cc := tr.NewClientConn(conn)
				_, err := cc.RoundTrip(req)
				Expect(err).To(HaveOccurred())
				Eventually(closed).Should(BeClosed())
			})

			It("cancels the stream when the HEADERS frame is too large", func() {
				tr := &Transport{MaxResponseHeaderBytes: 1337}
				cc := tr.NewClientConn(conn)
				b := (&headersFrame{Length: 1338}).Append(nil)
				r := bytes.NewReader(b)
				str.EXPECT().CancelRead(quic.StreamErrorCode(ErrCodeFrameError))
				str.EXPECT().CancelWrite(quic.StreamErrorCode(ErrCodeFrameError))
				closed := make(chan struct{})
				str.EXPECT().Close().Do(func() error { close(closed); return nil })
				str.EXPECT().Read(gomock.Any()).DoAndReturn(r.Read).AnyTimes()
				_, err := cc.RoundTrip(req)
				Expect(err).To(MatchError("http3: HEADERS frame too large: 1338 bytes (max: 1337)"))
				Eventually(closed).Should(BeClosed())
			})

			It("opens a request stream", func() {
				tr := &Transport{}
				cc := tr.NewClientConn(conn)
				conn.HandshakeComplete()
				str, err := cc.OpenRequestStream(context.Background())
				Expect(err).ToNot(HaveOccurred())
				Expect(str.SendRequestHeader(req)).To(Succeed())
				str.Write([]byte("foobar"))
				d := dataFrame{Length: 6}
				data := d.Append([]byte{})
				data = append(data, []byte("foobar")...)
				Expect(bytes.Contains(strBuf.Bytes(), data)).To(BeTrue())
			})
		})

		Context("request cancellations", func() {
			It("cancels a request while waiting for the handshake to complete", func() {
				ctx, cancel := context.WithCancel(context.Background())
				req := req.WithContext(ctx)
				conn.EXPECT().HandshakeComplete().Return(make(chan struct{}))

				tr := &Transport{}
				cc := tr.NewClientConn(conn)
				errChan := make(chan error)
				go func() {
					_, err := cc.RoundTrip(req)
					errChan <- err
				}()
				Consistently(errChan).ShouldNot(Receive())
				cancel()
				Eventually(errChan).Should(Receive(MatchError("context canceled")))
			})

			It("cancels a request while the request is still in flight", func() {
				ctx, cancel := context.WithCancel(context.Background())
				req := req.WithContext(ctx)
				conn.EXPECT().HandshakeComplete().Return(handshakeChan)
				conn.EXPECT().OpenStreamSync(ctx).Return(str, nil)
				buf := &bytes.Buffer{}
				str.EXPECT().Close().MaxTimes(1)
				str.EXPECT().Write(gomock.Any()).DoAndReturn(buf.Write)

				done := make(chan struct{})
				canceled := make(chan struct{})
				gomock.InOrder(
					str.EXPECT().CancelWrite(quic.StreamErrorCode(ErrCodeRequestCanceled)).Do(func(quic.StreamErrorCode) { close(canceled) }),
					str.EXPECT().CancelRead(quic.StreamErrorCode(ErrCodeRequestCanceled)).Do(func(quic.StreamErrorCode) { close(done) }),
				)
				str.EXPECT().CancelWrite(gomock.Any()).MaxTimes(1)
				str.EXPECT().CancelRead(gomock.Any()).MaxTimes(1)
				str.EXPECT().Read(gomock.Any()).DoAndReturn(func([]byte) (int, error) {
					cancel()
					<-canceled
					return 0, errors.New("test done")
				})
				tr := &Transport{}
				cc := tr.NewClientConn(conn)
				_, err := cc.RoundTrip(req)
				Expect(err).To(MatchError(context.Canceled))
				Eventually(done).Should(BeClosed())
			})

			It("cancels a request after the response arrived", func() {
				rspBuf := bytes.NewBuffer(encodeResponse(404))

				ctx, cancel := context.WithCancel(context.Background())
				req := req.WithContext(ctx)
				conn.EXPECT().HandshakeComplete().Return(handshakeChan)
				conn.EXPECT().OpenStreamSync(ctx).Return(str, nil)
				conn.EXPECT().ConnectionState().Return(quic.ConnectionState{})
				buf := &bytes.Buffer{}
				str.EXPECT().Close().MaxTimes(1)

				done := make(chan struct{})
				str.EXPECT().Write(gomock.Any()).DoAndReturn(buf.Write)
				str.EXPECT().Read(gomock.Any()).DoAndReturn(rspBuf.Read).AnyTimes()
				str.EXPECT().CancelWrite(quic.StreamErrorCode(ErrCodeRequestCanceled))
				str.EXPECT().CancelRead(quic.StreamErrorCode(ErrCodeRequestCanceled)).Do(func(quic.StreamErrorCode) { close(done) })
				tr := &Transport{}
				cc := tr.NewClientConn(conn)
				_, err := cc.RoundTrip(req)
				Expect(err).ToNot(HaveOccurred())
				cancel()
				Eventually(done).Should(BeClosed())
			})
		})

		Context("gzip compression", func() {
			BeforeEach(func() {
				conn.EXPECT().HandshakeComplete().Return(handshakeChan)
			})

			It("adds the gzip header to requests", func() {
				conn.EXPECT().OpenStreamSync(context.Background()).Return(str, nil)
				buf := &bytes.Buffer{}
				str.EXPECT().Write(gomock.Any()).DoAndReturn(buf.Write)
				gomock.InOrder(
					str.EXPECT().Close(),
					// when the Read errors
					str.EXPECT().CancelRead(gomock.Any()).MaxTimes(1),
					str.EXPECT().CancelWrite(gomock.Any()).MaxTimes(1),
				)
				testErr := errors.New("test done")
				str.EXPECT().Read(gomock.Any()).Return(0, testErr)
				tr := &Transport{}
				cc := tr.NewClientConn(conn)
				_, err := cc.RoundTrip(req)
				Expect(err).To(MatchError(testErr))
				hfs := decodeHeader(buf)
				Expect(hfs).To(HaveKeyWithValue("accept-encoding", "gzip"))
			})

			It("doesn't add gzip if the header disable it", func() {
				tr := &Transport{DisableCompression: true}
				client := tr.NewClientConn(conn)
				conn.EXPECT().OpenStreamSync(context.Background()).Return(str, nil)
				buf := &bytes.Buffer{}
				str.EXPECT().Write(gomock.Any()).DoAndReturn(buf.Write)
				gomock.InOrder(
					str.EXPECT().Close(),
					// when the Read errors
					str.EXPECT().CancelRead(gomock.Any()).MaxTimes(1),
					str.EXPECT().CancelWrite(gomock.Any()).MaxTimes(1),
				)
				testErr := errors.New("test done")
				str.EXPECT().Read(gomock.Any()).Return(0, testErr)
				_, err := client.RoundTrip(req)
				Expect(err).To(MatchError(testErr))
				hfs := decodeHeader(buf)
				Expect(hfs).ToNot(HaveKey("accept-encoding"))
			})

			It("decompresses the response", func() {
				conn.EXPECT().OpenStreamSync(context.Background()).Return(str, nil)
				conn.EXPECT().ConnectionState().Return(quic.ConnectionState{})
				buf := &bytes.Buffer{}
				rstr := mockquic.NewMockStream(mockCtrl)
				rstr.EXPECT().StreamID().AnyTimes()
				rstr.EXPECT().Write(gomock.Any()).Do(buf.Write).AnyTimes()
				rw := newResponseWriter(newStream(rstr, nil, nil, func(r io.Reader, u uint64) error { return nil }), nil, false, nil)
				rw.Header().Set("Content-Encoding", "gzip")
				gz := gzip.NewWriter(rw)
				gz.Write([]byte("gzipped response"))
				gz.Close()
				rw.Flush()
				str.EXPECT().Write(gomock.Any()).AnyTimes().DoAndReturn(func(p []byte) (int, error) { return len(p), nil })
				str.EXPECT().Read(gomock.Any()).DoAndReturn(buf.Read).AnyTimes()
				str.EXPECT().Close()

				tr := &Transport{}
				cc := tr.NewClientConn(conn)
				rsp, err := cc.RoundTrip(req)
				Expect(err).ToNot(HaveOccurred())
				data, err := io.ReadAll(rsp.Body)
				Expect(err).ToNot(HaveOccurred())
				Expect(rsp.ContentLength).To(BeEquivalentTo(-1))
				Expect(string(data)).To(Equal("gzipped response"))
				Expect(rsp.Header.Get("Content-Encoding")).To(BeEmpty())
				Expect(rsp.Uncompressed).To(BeTrue())
			})

			It("only decompresses the response if the response contains the right content-encoding header", func() {
				conn.EXPECT().OpenStreamSync(context.Background()).Return(str, nil)
				conn.EXPECT().ConnectionState().Return(quic.ConnectionState{})
				buf := &bytes.Buffer{}
				rstr := mockquic.NewMockStream(mockCtrl)
				rstr.EXPECT().StreamID().AnyTimes()
				rstr.EXPECT().Write(gomock.Any()).Do(buf.Write).AnyTimes()
				rw := newResponseWriter(newStream(rstr, nil, nil, func(r io.Reader, u uint64) error { return nil }), nil, false, nil)
				rw.Write([]byte("not gzipped"))
				rw.Flush()
				str.EXPECT().Write(gomock.Any()).AnyTimes().DoAndReturn(func(p []byte) (int, error) { return len(p), nil })
				str.EXPECT().Read(gomock.Any()).DoAndReturn(buf.Read).AnyTimes()
				str.EXPECT().Close()

				tr := &Transport{}
				cc := tr.NewClientConn(conn)
				rsp, err := cc.RoundTrip(req)
				Expect(err).ToNot(HaveOccurred())
				data, err := io.ReadAll(rsp.Body)
				Expect(err).ToNot(HaveOccurred())
				Expect(string(data)).To(Equal("not gzipped"))
				Expect(rsp.Header.Get("Content-Encoding")).To(BeEmpty())
			})
		})

		Context("1xx status code", func() {
			It("continues to read next header if code is 103", func() {
				var (
					cnt    int
					status int
					hdr    textproto.MIMEHeader
				)
				header1 := "</style.css>; rel=preload; as=style"
				header2 := "</script.js>; rel=preload; as=script"
				ctx := httptrace.WithClientTrace(req.Context(), &httptrace.ClientTrace{
					Got1xxResponse: func(code int, header textproto.MIMEHeader) error {
						cnt++
						status = code
						hdr = header
						return nil
					},
				})
				req := req.WithContext(ctx)
				rspBuf := bytes.NewBuffer(encodeResponse(103))
				gomock.InOrder(
					conn.EXPECT().HandshakeComplete().Return(handshakeChan),
					conn.EXPECT().OpenStreamSync(ctx).Return(str, nil),
					conn.EXPECT().ConnectionState().Return(quic.ConnectionState{}),
				)
				str.EXPECT().Write(gomock.Any()).AnyTimes().DoAndReturn(func(p []byte) (int, error) { return len(p), nil })
				str.EXPECT().Close()
				str.EXPECT().Read(gomock.Any()).DoAndReturn(rspBuf.Read).AnyTimes()
				tr := &Transport{}
				cc := tr.NewClientConn(conn)
				rsp, err := cc.RoundTrip(req)
				Expect(err).ToNot(HaveOccurred())
				Expect(rsp.Proto).To(Equal("HTTP/3.0"))
				Expect(rsp.ProtoMajor).To(Equal(3))
				Expect(rsp.StatusCode).To(Equal(200))
				Expect(rsp.Header).To(HaveKeyWithValue("Link", []string{header1, header2}))
				Expect(status).To(Equal(103))
				Expect(cnt).To(Equal(1))
				Expect(hdr).To(HaveKeyWithValue("Link", []string{header1, header2}))
				Expect(rsp.Request).ToNot(BeNil())
			})

			It("doesn't continue to read next header if code is a terminal status", func() {
				cnt := 0
				status := 0
				ctx := httptrace.WithClientTrace(req.Context(), &httptrace.ClientTrace{
					Got1xxResponse: func(code int, header textproto.MIMEHeader) error {
						cnt++
						status = code
						return nil
					},
				})
				req := req.WithContext(ctx)
				rspBuf := bytes.NewBuffer(encodeResponse(101))
				gomock.InOrder(
					conn.EXPECT().HandshakeComplete().Return(handshakeChan),
					conn.EXPECT().OpenStreamSync(ctx).Return(str, nil),
					conn.EXPECT().ConnectionState().Return(quic.ConnectionState{}),
				)
				str.EXPECT().Write(gomock.Any()).AnyTimes().DoAndReturn(func(p []byte) (int, error) { return len(p), nil })
				str.EXPECT().Close()
				str.EXPECT().Read(gomock.Any()).DoAndReturn(rspBuf.Read).AnyTimes()
				tr := &Transport{}
				cc := tr.NewClientConn(conn)
				rsp, err := cc.RoundTrip(req)
				Expect(err).ToNot(HaveOccurred())
				Expect(rsp.Proto).To(Equal("HTTP/3.0"))
				Expect(rsp.ProtoMajor).To(Equal(3))
				Expect(rsp.StatusCode).To(Equal(101))
				Expect(status).To(Equal(0))
				Expect(cnt).To(Equal(0))
				Expect(rsp.Request).ToNot(BeNil())
			})
		})
	})
})
