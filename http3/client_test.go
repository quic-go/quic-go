package http3

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/lucas-clemente/quic-go"
	mockquic "github.com/lucas-clemente/quic-go/internal/mocks/quic"
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
	"github.com/lucas-clemente/quic-go/quicvarint"

	"github.com/golang/mock/gomock"
	"github.com/marten-seemann/qpack"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Client", func() {
	var (
		client       *client
		req          *http.Request
		origDialAddr = dialAddr
		handshakeCtx context.Context // an already canceled context
	)

	BeforeEach(func() {
		origDialAddr = dialAddr
		hostname := "quic.clemente.io:1337"
		var err error
		client, err = newClient(hostname, nil, &roundTripperOpts{MaxHeaderBytes: 1337}, nil, nil)
		Expect(err).ToNot(HaveOccurred())
		Expect(client.hostname).To(Equal(hostname))

		req, err = http.NewRequest("GET", "https://localhost:1337", nil)
		Expect(err).ToNot(HaveOccurred())

		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		handshakeCtx = ctx
	})

	AfterEach(func() {
		dialAddr = origDialAddr
	})

	It("rejects quic.Configs that allow multiple QUIC versions", func() {
		qconf := &quic.Config{
			Versions: []quic.VersionNumber{protocol.VersionDraft29, protocol.Version1},
		}
		_, err := newClient("localhost:1337", nil, &roundTripperOpts{}, qconf, nil)
		Expect(err).To(MatchError("can only use a single QUIC version for dialing a HTTP/3 connection"))
	})

	It("uses the default QUIC and TLS config if none is give", func() {
		client, err := newClient("localhost:1337", nil, &roundTripperOpts{}, nil, nil)
		Expect(err).ToNot(HaveOccurred())
		var dialAddrCalled bool
		dialAddr = func(_ context.Context, _ string, tlsConf *tls.Config, quicConf *quic.Config) (quic.EarlyConnection, error) {
			Expect(quicConf).To(Equal(defaultQuicConfig))
			Expect(tlsConf.NextProtos).To(Equal([]string{nextProtoH3}))
			Expect(quicConf.Versions).To(Equal([]protocol.VersionNumber{protocol.Version1}))
			dialAddrCalled = true
			return nil, errors.New("test done")
		}
		client.RoundTripOpt(req, RoundTripOpt{})
		Expect(dialAddrCalled).To(BeTrue())
	})

	It("adds the port to the hostname, if none is given", func() {
		client, err := newClient("quic.clemente.io", nil, &roundTripperOpts{}, nil, nil)
		Expect(err).ToNot(HaveOccurred())
		var dialAddrCalled bool
		dialAddr = func(_ context.Context, hostname string, _ *tls.Config, _ *quic.Config) (quic.EarlyConnection, error) {
			Expect(hostname).To(Equal("quic.clemente.io:443"))
			dialAddrCalled = true
			return nil, errors.New("test done")
		}
		req, err := http.NewRequest("GET", "https://quic.clemente.io:443", nil)
		Expect(err).ToNot(HaveOccurred())
		client.RoundTripOpt(req, RoundTripOpt{})
		Expect(dialAddrCalled).To(BeTrue())
	})

	It("uses the TLS config and QUIC config", func() {
		tlsConf := &tls.Config{
			ServerName: "foo.bar",
			NextProtos: []string{"proto foo", "proto bar"},
		}
		quicConf := &quic.Config{MaxIdleTimeout: time.Nanosecond}
		client, err := newClient("localhost:1337", tlsConf, &roundTripperOpts{}, quicConf, nil)
		Expect(err).ToNot(HaveOccurred())
		var dialAddrCalled bool
		dialAddr = func(_ context.Context, host string, tlsConfP *tls.Config, quicConfP *quic.Config) (quic.EarlyConnection, error) {
			Expect(host).To(Equal("localhost:1337"))
			Expect(tlsConfP.ServerName).To(Equal(tlsConf.ServerName))
			Expect(tlsConfP.NextProtos).To(Equal([]string{nextProtoH3}))
			Expect(quicConfP.MaxIdleTimeout).To(Equal(quicConf.MaxIdleTimeout))
			dialAddrCalled = true
			return nil, errors.New("test done")
		}
		client.RoundTripOpt(req, RoundTripOpt{})
		Expect(dialAddrCalled).To(BeTrue())
		// make sure the original tls.Config was not modified
		Expect(tlsConf.NextProtos).To(Equal([]string{"proto foo", "proto bar"}))
	})

	It("uses the custom dialer, if provided", func() {
		testErr := errors.New("test done")
		tlsConf := &tls.Config{ServerName: "foo.bar"}
		quicConf := &quic.Config{MaxIdleTimeout: 1337 * time.Second}
		ctx, cancel := context.WithTimeout(context.Background(), time.Hour)
		defer cancel()
		var dialerCalled bool
		dialer := func(ctxP context.Context, address string, tlsConfP *tls.Config, quicConfP *quic.Config) (quic.EarlyConnection, error) {
			Expect(ctxP).To(Equal(ctx))
			Expect(address).To(Equal("localhost:1337"))
			Expect(tlsConfP.ServerName).To(Equal("foo.bar"))
			Expect(quicConfP.MaxIdleTimeout).To(Equal(quicConf.MaxIdleTimeout))
			dialerCalled = true
			return nil, testErr
		}
		client, err := newClient("localhost:1337", tlsConf, &roundTripperOpts{}, quicConf, dialer)
		Expect(err).ToNot(HaveOccurred())
		_, err = client.RoundTripOpt(req.WithContext(ctx), RoundTripOpt{})
		Expect(err).To(MatchError(testErr))
		Expect(dialerCalled).To(BeTrue())
	})

	It("enables HTTP/3 Datagrams", func() {
		testErr := errors.New("handshake error")
		client, err := newClient("localhost:1337", nil, &roundTripperOpts{EnableDatagram: true}, nil, nil)
		Expect(err).ToNot(HaveOccurred())
		dialAddr = func(_ context.Context, _ string, _ *tls.Config, quicConf *quic.Config) (quic.EarlyConnection, error) {
			Expect(quicConf.EnableDatagrams).To(BeTrue())
			return nil, testErr
		}
		_, err = client.RoundTripOpt(req, RoundTripOpt{})
		Expect(err).To(MatchError(testErr))
	})

	It("errors when dialing fails", func() {
		testErr := errors.New("handshake error")
		client, err := newClient("localhost:1337", nil, &roundTripperOpts{}, nil, nil)
		Expect(err).ToNot(HaveOccurred())
		dialAddr = func(context.Context, string, *tls.Config, *quic.Config) (quic.EarlyConnection, error) {
			return nil, testErr
		}
		_, err = client.RoundTripOpt(req, RoundTripOpt{})
		Expect(err).To(MatchError(testErr))
	})

	It("closes correctly if connection was not created", func() {
		client, err := newClient("localhost:1337", nil, &roundTripperOpts{}, nil, nil)
		Expect(err).ToNot(HaveOccurred())
		Expect(client.Close()).To(Succeed())
	})

	Context("validating the address", func() {
		It("refuses to do requests for the wrong host", func() {
			req, err := http.NewRequest("https", "https://quic.clemente.io:1336/foobar.html", nil)
			Expect(err).ToNot(HaveOccurred())
			_, err = client.RoundTripOpt(req, RoundTripOpt{})
			Expect(err).To(MatchError("http3 client BUG: RoundTripOpt called for the wrong client (expected quic.clemente.io:1337, got quic.clemente.io:1336)"))
		})

		It("allows requests using a different scheme", func() {
			testErr := errors.New("handshake error")
			req, err := http.NewRequest("masque", "masque://quic.clemente.io:1337/foobar.html", nil)
			Expect(err).ToNot(HaveOccurred())
			dialAddr = func(context.Context, string, *tls.Config, *quic.Config) (quic.EarlyConnection, error) {
				return nil, testErr
			}
			_, err = client.RoundTripOpt(req, RoundTripOpt{})
			Expect(err).To(MatchError(testErr))
		})
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
			controlStr.EXPECT().Write(gomock.Any()).Do(func(b []byte) {
				defer GinkgoRecover()
				close(settingsFrameWritten)
			})
			conn = mockquic.NewMockEarlyConnection(mockCtrl)
			conn.EXPECT().OpenUniStream().Return(controlStr, nil)
			conn.EXPECT().HandshakeComplete().Return(handshakeCtx)
			conn.EXPECT().OpenStreamSync(gomock.Any()).Return(nil, errors.New("done"))
			conn.EXPECT().AcceptUniStream(gomock.Any()).Return(nil, errors.New("done")).AnyTimes()
			dialAddr = func(context.Context, string, *tls.Config, *quic.Config) (quic.EarlyConnection, error) {
				return conn, nil
			}
			var err error
			request, err = http.NewRequest("GET", "https://quic.clemente.io:1337/file1.dat", nil)
			Expect(err).ToNot(HaveOccurred())
		})

		AfterEach(func() {
			testDone <- struct{}{}
			Eventually(settingsFrameWritten).Should(BeClosed())
		})

		It("hijacks a bidirectional stream of unknown frame type", func() {
			frameTypeChan := make(chan FrameType, 1)
			client.opts.StreamHijacker = func(ft FrameType, c quic.Connection, s quic.Stream, e error) (hijacked bool, err error) {
				Expect(e).ToNot(HaveOccurred())
				frameTypeChan <- ft
				return true, nil
			}

			buf := &bytes.Buffer{}
			quicvarint.Write(buf, 0x41)
			unknownStr := mockquic.NewMockStream(mockCtrl)
			unknownStr.EXPECT().Read(gomock.Any()).DoAndReturn(buf.Read).AnyTimes()
			conn.EXPECT().AcceptStream(gomock.Any()).Return(unknownStr, nil)
			conn.EXPECT().AcceptStream(gomock.Any()).DoAndReturn(func(context.Context) (quic.Stream, error) {
				<-testDone
				return nil, errors.New("test done")
			})
			_, err := client.RoundTripOpt(request, RoundTripOpt{})
			Expect(err).To(MatchError("done"))
			Eventually(frameTypeChan).Should(Receive(BeEquivalentTo(0x41)))
			time.Sleep(scaleDuration(20 * time.Millisecond)) // don't EXPECT any calls to conn.CloseWithError
		})

		It("closes the connection when hijacker didn't hijack a bidirectional stream", func() {
			frameTypeChan := make(chan FrameType, 1)
			client.opts.StreamHijacker = func(ft FrameType, c quic.Connection, s quic.Stream, e error) (hijacked bool, err error) {
				Expect(e).ToNot(HaveOccurred())
				frameTypeChan <- ft
				return false, nil
			}

			buf := &bytes.Buffer{}
			quicvarint.Write(buf, 0x41)
			unknownStr := mockquic.NewMockStream(mockCtrl)
			unknownStr.EXPECT().Read(gomock.Any()).DoAndReturn(buf.Read).AnyTimes()
			conn.EXPECT().AcceptStream(gomock.Any()).Return(unknownStr, nil)
			conn.EXPECT().AcceptStream(gomock.Any()).DoAndReturn(func(context.Context) (quic.Stream, error) {
				<-testDone
				return nil, errors.New("test done")
			})
			conn.EXPECT().CloseWithError(quic.ApplicationErrorCode(errorFrameUnexpected), gomock.Any()).Return(nil).AnyTimes()
			_, err := client.RoundTripOpt(request, RoundTripOpt{})
			Expect(err).To(MatchError("done"))
			Eventually(frameTypeChan).Should(Receive(BeEquivalentTo(0x41)))
		})

		It("closes the connection when hijacker returned error", func() {
			frameTypeChan := make(chan FrameType, 1)
			client.opts.StreamHijacker = func(ft FrameType, c quic.Connection, s quic.Stream, e error) (hijacked bool, err error) {
				Expect(e).ToNot(HaveOccurred())
				frameTypeChan <- ft
				return false, errors.New("error in hijacker")
			}

			buf := &bytes.Buffer{}
			quicvarint.Write(buf, 0x41)
			unknownStr := mockquic.NewMockStream(mockCtrl)
			unknownStr.EXPECT().Read(gomock.Any()).DoAndReturn(buf.Read).AnyTimes()
			conn.EXPECT().AcceptStream(gomock.Any()).Return(unknownStr, nil)
			conn.EXPECT().AcceptStream(gomock.Any()).DoAndReturn(func(context.Context) (quic.Stream, error) {
				<-testDone
				return nil, errors.New("test done")
			})
			conn.EXPECT().CloseWithError(quic.ApplicationErrorCode(errorFrameUnexpected), gomock.Any()).Return(nil).AnyTimes()
			_, err := client.RoundTripOpt(request, RoundTripOpt{})
			Expect(err).To(MatchError("done"))
			Eventually(frameTypeChan).Should(Receive(BeEquivalentTo(0x41)))
		})

		It("handles errors that occur when reading the frame type", func() {
			testErr := errors.New("test error")
			unknownStr := mockquic.NewMockStream(mockCtrl)
			done := make(chan struct{})
			client.opts.StreamHijacker = func(ft FrameType, c quic.Connection, str quic.Stream, e error) (hijacked bool, err error) {
				defer close(done)
				Expect(e).To(MatchError(testErr))
				Expect(ft).To(BeZero())
				Expect(str).To(Equal(unknownStr))
				return false, nil
			}

			unknownStr.EXPECT().Read(gomock.Any()).Return(0, testErr).AnyTimes()
			conn.EXPECT().AcceptStream(gomock.Any()).Return(unknownStr, nil)
			conn.EXPECT().AcceptStream(gomock.Any()).DoAndReturn(func(context.Context) (quic.Stream, error) {
				<-testDone
				return nil, errors.New("test done")
			})
			conn.EXPECT().CloseWithError(quic.ApplicationErrorCode(errorFrameUnexpected), gomock.Any()).Return(nil).AnyTimes()
			_, err := client.RoundTripOpt(request, RoundTripOpt{})
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
			controlStr.EXPECT().Write(gomock.Any()).Do(func(b []byte) {
				defer GinkgoRecover()
				close(settingsFrameWritten)
			})
			conn = mockquic.NewMockEarlyConnection(mockCtrl)
			conn.EXPECT().OpenUniStream().Return(controlStr, nil)
			conn.EXPECT().HandshakeComplete().Return(handshakeCtx)
			conn.EXPECT().OpenStreamSync(gomock.Any()).Return(nil, errors.New("done"))
			dialAddr = func(context.Context, string, *tls.Config, *quic.Config) (quic.EarlyConnection, error) {
				return conn, nil
			}
			var err error
			req, err = http.NewRequest("GET", "https://quic.clemente.io:1337/file1.dat", nil)
			Expect(err).ToNot(HaveOccurred())
		})

		AfterEach(func() {
			testDone <- struct{}{}
			Eventually(settingsFrameWritten).Should(BeClosed())
		})

		It("hijacks an unidirectional stream of unknown stream type", func() {
			streamTypeChan := make(chan StreamType, 1)
			client.opts.UniStreamHijacker = func(st StreamType, _ quic.Connection, _ quic.ReceiveStream, err error) bool {
				Expect(err).ToNot(HaveOccurred())
				streamTypeChan <- st
				return true
			}

			buf := &bytes.Buffer{}
			quicvarint.Write(buf, 0x54)
			unknownStr := mockquic.NewMockStream(mockCtrl)
			unknownStr.EXPECT().Read(gomock.Any()).DoAndReturn(buf.Read).AnyTimes()
			conn.EXPECT().AcceptUniStream(gomock.Any()).DoAndReturn(func(context.Context) (quic.ReceiveStream, error) {
				return unknownStr, nil
			})
			conn.EXPECT().AcceptUniStream(gomock.Any()).DoAndReturn(func(context.Context) (quic.ReceiveStream, error) {
				<-testDone
				return nil, errors.New("test done")
			})
			_, err := client.RoundTripOpt(req, RoundTripOpt{})
			Expect(err).To(MatchError("done"))
			Eventually(streamTypeChan).Should(Receive(BeEquivalentTo(0x54)))
			time.Sleep(scaleDuration(20 * time.Millisecond)) // don't EXPECT any calls to conn.CloseWithError
		})

		It("handles errors that occur when reading the stream type", func() {
			testErr := errors.New("test error")
			done := make(chan struct{})
			unknownStr := mockquic.NewMockStream(mockCtrl)
			client.opts.UniStreamHijacker = func(st StreamType, _ quic.Connection, str quic.ReceiveStream, err error) bool {
				defer close(done)
				Expect(st).To(BeZero())
				Expect(str).To(Equal(unknownStr))
				Expect(err).To(MatchError(testErr))
				return true
			}

			unknownStr.EXPECT().Read(gomock.Any()).Return(0, testErr)
			conn.EXPECT().AcceptUniStream(gomock.Any()).Return(unknownStr, nil)
			conn.EXPECT().AcceptUniStream(gomock.Any()).DoAndReturn(func(context.Context) (quic.ReceiveStream, error) {
				<-testDone
				return nil, errors.New("test done")
			})
			_, err := client.RoundTripOpt(req, RoundTripOpt{})
			Expect(err).To(MatchError("done"))
			Eventually(done).Should(BeClosed())
			time.Sleep(scaleDuration(20 * time.Millisecond)) // don't EXPECT any calls to conn.CloseWithError
		})

		It("cancels reading when hijacker didn't hijack an unidirectional stream", func() {
			streamTypeChan := make(chan StreamType, 1)
			client.opts.UniStreamHijacker = func(st StreamType, _ quic.Connection, _ quic.ReceiveStream, err error) bool {
				Expect(err).ToNot(HaveOccurred())
				streamTypeChan <- st
				return false
			}

			buf := &bytes.Buffer{}
			quicvarint.Write(buf, 0x54)
			unknownStr := mockquic.NewMockStream(mockCtrl)
			unknownStr.EXPECT().Read(gomock.Any()).DoAndReturn(buf.Read).AnyTimes()
			unknownStr.EXPECT().CancelRead(quic.StreamErrorCode(errorStreamCreationError))
			conn.EXPECT().AcceptUniStream(gomock.Any()).DoAndReturn(func(context.Context) (quic.ReceiveStream, error) {
				return unknownStr, nil
			})
			conn.EXPECT().AcceptUniStream(gomock.Any()).DoAndReturn(func(context.Context) (quic.ReceiveStream, error) {
				<-testDone
				return nil, errors.New("test done")
			})
			_, err := client.RoundTripOpt(req, RoundTripOpt{})
			Expect(err).To(MatchError("done"))
			Eventually(streamTypeChan).Should(Receive(BeEquivalentTo(0x54)))
			time.Sleep(scaleDuration(20 * time.Millisecond)) // don't EXPECT any calls to conn.CloseWithError
		})
	})

	Context("control stream handling", func() {
		var (
			req                  *http.Request
			conn                 *mockquic.MockEarlyConnection
			settingsFrameWritten chan struct{}
		)
		testDone := make(chan struct{})

		BeforeEach(func() {
			settingsFrameWritten = make(chan struct{})
			controlStr := mockquic.NewMockStream(mockCtrl)
			controlStr.EXPECT().Write(gomock.Any()).Do(func(b []byte) {
				defer GinkgoRecover()
				close(settingsFrameWritten)
			})
			conn = mockquic.NewMockEarlyConnection(mockCtrl)
			conn.EXPECT().OpenUniStream().Return(controlStr, nil)
			conn.EXPECT().HandshakeComplete().Return(handshakeCtx)
			conn.EXPECT().OpenStreamSync(gomock.Any()).Return(nil, errors.New("done"))
			dialAddr = func(context.Context, string, *tls.Config, *quic.Config) (quic.EarlyConnection, error) {
				return conn, nil
			}
			var err error
			req, err = http.NewRequest("GET", "https://quic.clemente.io:1337/file1.dat", nil)
			Expect(err).ToNot(HaveOccurred())
		})

		AfterEach(func() {
			testDone <- struct{}{}
			Eventually(settingsFrameWritten).Should(BeClosed())
		})

		It("parses the SETTINGS frame", func() {
			buf := &bytes.Buffer{}
			quicvarint.Write(buf, streamTypeControlStream)
			(&settingsFrame{}).Write(buf)
			controlStr := mockquic.NewMockStream(mockCtrl)
			controlStr.EXPECT().Read(gomock.Any()).DoAndReturn(buf.Read).AnyTimes()
			conn.EXPECT().AcceptUniStream(gomock.Any()).DoAndReturn(func(context.Context) (quic.ReceiveStream, error) {
				return controlStr, nil
			})
			conn.EXPECT().AcceptUniStream(gomock.Any()).DoAndReturn(func(context.Context) (quic.ReceiveStream, error) {
				<-testDone
				return nil, errors.New("test done")
			})
			_, err := client.RoundTripOpt(req, RoundTripOpt{})
			Expect(err).To(MatchError("done"))
			time.Sleep(scaleDuration(20 * time.Millisecond)) // don't EXPECT any calls to conn.CloseWithError
		})

		for _, t := range []uint64{streamTypeQPACKEncoderStream, streamTypeQPACKDecoderStream} {
			streamType := t
			name := "encoder"
			if streamType == streamTypeQPACKDecoderStream {
				name = "decoder"
			}

			It(fmt.Sprintf("ignores the QPACK %s streams", name), func() {
				buf := &bytes.Buffer{}
				quicvarint.Write(buf, streamType)
				str := mockquic.NewMockStream(mockCtrl)
				str.EXPECT().Read(gomock.Any()).DoAndReturn(buf.Read).AnyTimes()

				conn.EXPECT().AcceptUniStream(gomock.Any()).DoAndReturn(func(context.Context) (quic.ReceiveStream, error) {
					return str, nil
				})
				conn.EXPECT().AcceptUniStream(gomock.Any()).DoAndReturn(func(context.Context) (quic.ReceiveStream, error) {
					<-testDone
					return nil, errors.New("test done")
				})
				_, err := client.RoundTripOpt(req, RoundTripOpt{})
				Expect(err).To(MatchError("done"))
				time.Sleep(scaleDuration(20 * time.Millisecond)) // don't EXPECT any calls to str.CancelRead
			})
		}

		It("resets streams Other than the control stream and the QPACK streams", func() {
			buf := &bytes.Buffer{}
			quicvarint.Write(buf, 1337)
			str := mockquic.NewMockStream(mockCtrl)
			str.EXPECT().Read(gomock.Any()).DoAndReturn(buf.Read).AnyTimes()
			done := make(chan struct{})
			str.EXPECT().CancelRead(quic.StreamErrorCode(errorStreamCreationError)).Do(func(code quic.StreamErrorCode) {
				close(done)
			})

			conn.EXPECT().AcceptUniStream(gomock.Any()).DoAndReturn(func(context.Context) (quic.ReceiveStream, error) {
				return str, nil
			})
			conn.EXPECT().AcceptUniStream(gomock.Any()).DoAndReturn(func(context.Context) (quic.ReceiveStream, error) {
				<-testDone
				return nil, errors.New("test done")
			})
			_, err := client.RoundTripOpt(req, RoundTripOpt{})
			Expect(err).To(MatchError("done"))
			Eventually(done).Should(BeClosed())
		})

		It("errors when the first frame on the control stream is not a SETTINGS frame", func() {
			buf := &bytes.Buffer{}
			quicvarint.Write(buf, streamTypeControlStream)
			(&dataFrame{}).Write(buf)
			controlStr := mockquic.NewMockStream(mockCtrl)
			controlStr.EXPECT().Read(gomock.Any()).DoAndReturn(buf.Read).AnyTimes()
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
				Expect(code).To(BeEquivalentTo(errorMissingSettings))
				close(done)
			})
			_, err := client.RoundTripOpt(req, RoundTripOpt{})
			Expect(err).To(MatchError("done"))
			Eventually(done).Should(BeClosed())
		})

		It("errors when parsing the frame on the control stream fails", func() {
			buf := &bytes.Buffer{}
			quicvarint.Write(buf, streamTypeControlStream)
			b := &bytes.Buffer{}
			(&settingsFrame{}).Write(b)
			buf.Write(b.Bytes()[:b.Len()-1])
			controlStr := mockquic.NewMockStream(mockCtrl)
			controlStr.EXPECT().Read(gomock.Any()).DoAndReturn(buf.Read).AnyTimes()
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
				Expect(code).To(BeEquivalentTo(errorFrameError))
				close(done)
			})
			_, err := client.RoundTripOpt(req, RoundTripOpt{})
			Expect(err).To(MatchError("done"))
			Eventually(done).Should(BeClosed())
		})

		It("errors when parsing the server opens a push stream", func() {
			buf := &bytes.Buffer{}
			quicvarint.Write(buf, streamTypePushStream)
			controlStr := mockquic.NewMockStream(mockCtrl)
			controlStr.EXPECT().Read(gomock.Any()).DoAndReturn(buf.Read).AnyTimes()
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
				Expect(code).To(BeEquivalentTo(errorIDError))
				close(done)
			})
			_, err := client.RoundTripOpt(req, RoundTripOpt{})
			Expect(err).To(MatchError("done"))
			Eventually(done).Should(BeClosed())
		})

		It("errors when the server advertises datagram support (and we enabled support for it)", func() {
			client.opts.EnableDatagram = true
			buf := &bytes.Buffer{}
			quicvarint.Write(buf, streamTypeControlStream)
			(&settingsFrame{Datagram: true}).Write(buf)
			controlStr := mockquic.NewMockStream(mockCtrl)
			controlStr.EXPECT().Read(gomock.Any()).DoAndReturn(buf.Read).AnyTimes()
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
				Expect(code).To(BeEquivalentTo(errorSettingsError))
				Expect(reason).To(Equal("missing QUIC Datagram support"))
				close(done)
			})
			_, err := client.RoundTripOpt(req, RoundTripOpt{})
			Expect(err).To(MatchError("done"))
			Eventually(done).Should(BeClosed())
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

		getHeadersFrame := func(headers map[string]string) []byte {
			buf := &bytes.Buffer{}
			headerBuf := &bytes.Buffer{}
			enc := qpack.NewEncoder(headerBuf)
			for name, value := range headers {
				Expect(enc.WriteField(qpack.HeaderField{Name: name, Value: value})).To(Succeed())
			}
			Expect(enc.Close()).To(Succeed())
			(&headersFrame{Length: uint64(headerBuf.Len())}).Write(buf)
			buf.Write(headerBuf.Bytes())
			return buf.Bytes()
		}

		decodeHeader := func(str io.Reader) map[string]string {
			fields := make(map[string]string)
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
				fields[p.Name] = p.Value
			}
			return fields
		}

		getResponse := func(status int) []byte {
			buf := &bytes.Buffer{}
			rstr := mockquic.NewMockStream(mockCtrl)
			rstr.EXPECT().Write(gomock.Any()).Do(buf.Write).AnyTimes()
			rw := newResponseWriter(rstr, nil, utils.DefaultLogger)
			rw.WriteHeader(status)
			rw.Flush()
			return buf.Bytes()
		}

		BeforeEach(func() {
			settingsFrameWritten = make(chan struct{})
			controlStr := mockquic.NewMockStream(mockCtrl)
			controlStr.EXPECT().Write(gomock.Any()).Do(func(b []byte) {
				defer GinkgoRecover()
				r := bytes.NewReader(b)
				streamType, err := quicvarint.Read(r)
				Expect(err).ToNot(HaveOccurred())
				Expect(streamType).To(BeEquivalentTo(streamTypeControlStream))
				close(settingsFrameWritten)
			}) // SETTINGS frame
			str = mockquic.NewMockStream(mockCtrl)
			conn = mockquic.NewMockEarlyConnection(mockCtrl)
			conn.EXPECT().OpenUniStream().Return(controlStr, nil)
			conn.EXPECT().AcceptUniStream(gomock.Any()).DoAndReturn(func(context.Context) (quic.ReceiveStream, error) {
				<-testDone
				return nil, errors.New("test done")
			})
			dialAddr = func(context.Context, string, *tls.Config, *quic.Config) (quic.EarlyConnection, error) {
				return conn, nil
			}
			var err error
			req, err = http.NewRequest("GET", "https://quic.clemente.io:1337/file1.dat", nil)
			Expect(err).ToNot(HaveOccurred())
		})

		AfterEach(func() {
			testDone <- struct{}{}
			Eventually(settingsFrameWritten).Should(BeClosed())
		})

		It("errors if it can't open a stream", func() {
			testErr := errors.New("stream open error")
			conn.EXPECT().OpenStreamSync(context.Background()).Return(nil, testErr)
			conn.EXPECT().CloseWithError(gomock.Any(), gomock.Any()).MaxTimes(1)
			conn.EXPECT().HandshakeComplete().Return(handshakeCtx)
			_, err := client.RoundTripOpt(req, RoundTripOpt{})
			Expect(err).To(MatchError(testErr))
		})

		It("performs a 0-RTT request", func() {
			testErr := errors.New("stream open error")
			req.Method = MethodGet0RTT
			// don't EXPECT any calls to HandshakeComplete()
			conn.EXPECT().OpenStreamSync(context.Background()).Return(str, nil)
			buf := &bytes.Buffer{}
			str.EXPECT().Write(gomock.Any()).DoAndReturn(buf.Write).AnyTimes()
			str.EXPECT().Close()
			str.EXPECT().CancelWrite(gomock.Any())
			str.EXPECT().Read(gomock.Any()).DoAndReturn(func([]byte) (int, error) {
				return 0, testErr
			})
			_, err := client.RoundTripOpt(req, RoundTripOpt{})
			Expect(err).To(MatchError(testErr))
			Expect(decodeHeader(buf)).To(HaveKeyWithValue(":method", "GET"))
		})

		It("returns a response", func() {
			rspBuf := bytes.NewBuffer(getResponse(418))
			gomock.InOrder(
				conn.EXPECT().HandshakeComplete().Return(handshakeCtx),
				conn.EXPECT().OpenStreamSync(context.Background()).Return(str, nil),
				conn.EXPECT().ConnectionState().Return(quic.ConnectionState{}),
			)
			str.EXPECT().Write(gomock.Any()).AnyTimes().DoAndReturn(func(p []byte) (int, error) { return len(p), nil })
			str.EXPECT().Close()
			str.EXPECT().Read(gomock.Any()).DoAndReturn(rspBuf.Read).AnyTimes()
			rsp, err := client.RoundTripOpt(req, RoundTripOpt{})
			Expect(err).ToNot(HaveOccurred())
			Expect(rsp.Proto).To(Equal("HTTP/3.0"))
			Expect(rsp.ProtoMajor).To(Equal(3))
			Expect(rsp.StatusCode).To(Equal(418))
		})

		Context("requests containing a Body", func() {
			var strBuf *bytes.Buffer

			BeforeEach(func() {
				strBuf = &bytes.Buffer{}
				gomock.InOrder(
					conn.EXPECT().HandshakeComplete().Return(handshakeCtx),
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
					str.EXPECT().Close().Do(func() { close(done) }),
					str.EXPECT().CancelWrite(gomock.Any()).MaxTimes(1), // when reading the response errors
				)
				// the response body is sent asynchronously, while already reading the response
				str.EXPECT().Read(gomock.Any()).DoAndReturn(func([]byte) (int, error) {
					<-done
					return 0, errors.New("test done")
				})
				_, err := client.RoundTripOpt(req, RoundTripOpt{})
				Expect(err).To(MatchError("test done"))
				hfs := decodeHeader(strBuf)
				Expect(hfs).To(HaveKeyWithValue(":method", "POST"))
				Expect(hfs).To(HaveKeyWithValue(":path", "/upload"))
			})

			It("returns the error that occurred when reading the body", func() {
				req.Body.(*mockBody).readErr = errors.New("testErr")
				done := make(chan struct{})
				gomock.InOrder(
					str.EXPECT().CancelWrite(quic.StreamErrorCode(errorRequestCanceled)).Do(func(quic.StreamErrorCode) {
						close(done)
					}),
					str.EXPECT().CancelWrite(gomock.Any()),
				)

				// the response body is sent asynchronously, while already reading the response
				str.EXPECT().Read(gomock.Any()).DoAndReturn(func([]byte) (int, error) {
					<-done
					return 0, errors.New("test done")
				})
				closed := make(chan struct{})
				str.EXPECT().Close().Do(func() { close(closed) })
				_, err := client.RoundTripOpt(req, RoundTripOpt{})
				Expect(err).To(MatchError("test done"))
				Eventually(closed).Should(BeClosed())
			})

			It("sets the Content-Length", func() {
				done := make(chan struct{})
				buf := &bytes.Buffer{}
				buf.Write(getHeadersFrame(map[string]string{
					":status":        "200",
					"Content-Length": "1337",
				}))
				(&dataFrame{Length: 0x6}).Write(buf)
				buf.Write([]byte("foobar"))
				str.EXPECT().Close().Do(func() { close(done) })
				conn.EXPECT().ConnectionState().Return(quic.ConnectionState{})
				str.EXPECT().CancelWrite(gomock.Any()).MaxTimes(1) // when reading the response errors
				// the response body is sent asynchronously, while already reading the response
				str.EXPECT().Read(gomock.Any()).DoAndReturn(buf.Read).AnyTimes()
				req, err := client.RoundTripOpt(req, RoundTripOpt{})
				Expect(err).ToNot(HaveOccurred())
				Expect(req.ContentLength).To(BeEquivalentTo(1337))
				Eventually(done).Should(BeClosed())
			})

			It("closes the connection when the first frame is not a HEADERS frame", func() {
				buf := &bytes.Buffer{}
				(&dataFrame{Length: 0x42}).Write(buf)
				conn.EXPECT().CloseWithError(quic.ApplicationErrorCode(errorFrameUnexpected), gomock.Any())
				closed := make(chan struct{})
				str.EXPECT().Close().Do(func() { close(closed) })
				str.EXPECT().Read(gomock.Any()).DoAndReturn(buf.Read).AnyTimes()
				_, err := client.RoundTripOpt(req, RoundTripOpt{})
				Expect(err).To(MatchError("expected first frame to be a HEADERS frame"))
				Eventually(closed).Should(BeClosed())
			})

			It("cancels the stream when the HEADERS frame is too large", func() {
				buf := &bytes.Buffer{}
				(&headersFrame{Length: 1338}).Write(buf)
				str.EXPECT().CancelWrite(quic.StreamErrorCode(errorFrameError))
				closed := make(chan struct{})
				str.EXPECT().Close().Do(func() { close(closed) })
				str.EXPECT().Read(gomock.Any()).DoAndReturn(buf.Read).AnyTimes()
				_, err := client.RoundTripOpt(req, RoundTripOpt{})
				Expect(err).To(MatchError("HEADERS frame too large: 1338 bytes (max: 1337)"))
				Eventually(closed).Should(BeClosed())
			})
		})

		Context("request cancellations", func() {
			It("cancels a request while waiting for the handshake to complete", func() {
				ctx, cancel := context.WithCancel(context.Background())
				req := req.WithContext(ctx)
				conn.EXPECT().HandshakeComplete().Return(context.Background())

				errChan := make(chan error)
				go func() {
					_, err := client.RoundTripOpt(req, RoundTripOpt{})
					errChan <- err
				}()
				Consistently(errChan).ShouldNot(Receive())
				cancel()
				Eventually(errChan).Should(Receive(MatchError("context canceled")))
			})

			It("cancels a request while the request is still in flight", func() {
				ctx, cancel := context.WithCancel(context.Background())
				req := req.WithContext(ctx)
				conn.EXPECT().HandshakeComplete().Return(handshakeCtx)
				conn.EXPECT().OpenStreamSync(ctx).Return(str, nil)
				buf := &bytes.Buffer{}
				str.EXPECT().Close().MaxTimes(1)

				str.EXPECT().Write(gomock.Any()).DoAndReturn(buf.Write)

				done := make(chan struct{})
				canceled := make(chan struct{})
				gomock.InOrder(
					str.EXPECT().CancelWrite(quic.StreamErrorCode(errorRequestCanceled)).Do(func(quic.StreamErrorCode) { close(canceled) }),
					str.EXPECT().CancelRead(quic.StreamErrorCode(errorRequestCanceled)).Do(func(quic.StreamErrorCode) { close(done) }),
				)
				str.EXPECT().CancelWrite(gomock.Any()).MaxTimes(1)
				str.EXPECT().Read(gomock.Any()).DoAndReturn(func([]byte) (int, error) {
					cancel()
					<-canceled
					return 0, errors.New("test done")
				})
				_, err := client.RoundTripOpt(req, RoundTripOpt{})
				Expect(err).To(MatchError("test done"))
				Eventually(done).Should(BeClosed())
			})

			It("cancels a request after the response arrived", func() {
				rspBuf := bytes.NewBuffer(getResponse(404))

				ctx, cancel := context.WithCancel(context.Background())
				req := req.WithContext(ctx)
				conn.EXPECT().HandshakeComplete().Return(handshakeCtx)
				conn.EXPECT().OpenStreamSync(ctx).Return(str, nil)
				conn.EXPECT().ConnectionState().Return(quic.ConnectionState{})
				buf := &bytes.Buffer{}
				str.EXPECT().Close().MaxTimes(1)

				done := make(chan struct{})
				str.EXPECT().Write(gomock.Any()).DoAndReturn(buf.Write)
				str.EXPECT().Read(gomock.Any()).DoAndReturn(rspBuf.Read).AnyTimes()
				str.EXPECT().CancelWrite(quic.StreamErrorCode(errorRequestCanceled))
				str.EXPECT().CancelRead(quic.StreamErrorCode(errorRequestCanceled)).Do(func(quic.StreamErrorCode) { close(done) })
				_, err := client.RoundTripOpt(req, RoundTripOpt{})
				Expect(err).ToNot(HaveOccurred())
				cancel()
				Eventually(done).Should(BeClosed())
			})
		})

		Context("gzip compression", func() {
			BeforeEach(func() {
				conn.EXPECT().HandshakeComplete().Return(handshakeCtx)
			})

			It("adds the gzip header to requests", func() {
				conn.EXPECT().OpenStreamSync(context.Background()).Return(str, nil)
				buf := &bytes.Buffer{}
				str.EXPECT().Write(gomock.Any()).DoAndReturn(buf.Write)
				gomock.InOrder(
					str.EXPECT().Close(),
					str.EXPECT().CancelWrite(gomock.Any()).MaxTimes(1), // when the Read errors
				)
				str.EXPECT().Read(gomock.Any()).Return(0, errors.New("test done"))
				_, err := client.RoundTripOpt(req, RoundTripOpt{})
				Expect(err).To(MatchError("test done"))
				hfs := decodeHeader(buf)
				Expect(hfs).To(HaveKeyWithValue("accept-encoding", "gzip"))
			})

			It("doesn't add gzip if the header disable it", func() {
				client, err := newClient("quic.clemente.io:1337", nil, &roundTripperOpts{DisableCompression: true}, nil, nil)
				Expect(err).ToNot(HaveOccurred())
				conn.EXPECT().OpenStreamSync(context.Background()).Return(str, nil)
				buf := &bytes.Buffer{}
				str.EXPECT().Write(gomock.Any()).DoAndReturn(buf.Write)
				gomock.InOrder(
					str.EXPECT().Close(),
					str.EXPECT().CancelWrite(gomock.Any()).MaxTimes(1), // when the Read errors
				)
				str.EXPECT().Read(gomock.Any()).Return(0, errors.New("test done"))
				_, err = client.RoundTripOpt(req, RoundTripOpt{})
				Expect(err).To(MatchError("test done"))
				hfs := decodeHeader(buf)
				Expect(hfs).ToNot(HaveKey("accept-encoding"))
			})

			It("decompresses the response", func() {
				conn.EXPECT().OpenStreamSync(context.Background()).Return(str, nil)
				conn.EXPECT().ConnectionState().Return(quic.ConnectionState{})
				buf := &bytes.Buffer{}
				rstr := mockquic.NewMockStream(mockCtrl)
				rstr.EXPECT().Write(gomock.Any()).Do(buf.Write).AnyTimes()
				rw := newResponseWriter(rstr, nil, utils.DefaultLogger)
				rw.Header().Set("Content-Encoding", "gzip")
				gz := gzip.NewWriter(rw)
				gz.Write([]byte("gzipped response"))
				gz.Close()
				rw.Flush()
				str.EXPECT().Write(gomock.Any()).AnyTimes().DoAndReturn(func(p []byte) (int, error) { return len(p), nil })
				str.EXPECT().Read(gomock.Any()).DoAndReturn(buf.Read).AnyTimes()
				str.EXPECT().Close()

				rsp, err := client.RoundTripOpt(req, RoundTripOpt{})
				Expect(err).ToNot(HaveOccurred())
				data, err := ioutil.ReadAll(rsp.Body)
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
				rstr.EXPECT().Write(gomock.Any()).Do(buf.Write).AnyTimes()
				rw := newResponseWriter(rstr, nil, utils.DefaultLogger)
				rw.Write([]byte("not gzipped"))
				rw.Flush()
				str.EXPECT().Write(gomock.Any()).AnyTimes().DoAndReturn(func(p []byte) (int, error) { return len(p), nil })
				str.EXPECT().Read(gomock.Any()).DoAndReturn(buf.Read).AnyTimes()
				str.EXPECT().Close()

				rsp, err := client.RoundTripOpt(req, RoundTripOpt{})
				Expect(err).ToNot(HaveOccurred())
				data, err := ioutil.ReadAll(rsp.Body)
				Expect(err).ToNot(HaveOccurred())
				Expect(string(data)).To(Equal("not gzipped"))
				Expect(rsp.Header.Get("Content-Encoding")).To(BeEmpty())
			})
		})
	})
})
