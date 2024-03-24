package http3

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/quic-go/quic-go"
	mockquic "github.com/quic-go/quic-go/internal/mocks/quic"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/qerr"
	"github.com/quic-go/quic-go/internal/utils"
	"github.com/quic-go/quic-go/quicvarint"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"go.uber.org/mock/gomock"
)

var _ = Describe("Connection", func() {
	Context("control stream handling", func() {
		It("parses the SETTINGS frame", func() {
			qconn := mockquic.NewMockEarlyConnection(mockCtrl)
			conn := newConnection(
				qconn,
				false,
				nil,
				protocol.PerspectiveServer,
				utils.DefaultLogger,
			)
			b := quicvarint.Append(nil, streamTypeControlStream)
			b = (&settingsFrame{
				Datagram:        true,
				ExtendedConnect: true,
				Other:           map[uint64]uint64{1337: 42},
			}).Append(b)
			r := bytes.NewReader(b)
			controlStr := mockquic.NewMockStream(mockCtrl)
			controlStr.EXPECT().Read(gomock.Any()).DoAndReturn(r.Read).AnyTimes()
			qconn.EXPECT().AcceptUniStream(gomock.Any()).Return(controlStr, nil)
			qconn.EXPECT().AcceptUniStream(gomock.Any()).Return(nil, errors.New("test done"))
			done := make(chan struct{})
			go func() {
				defer GinkgoRecover()
				defer close(done)
				conn.HandleUnidirectionalStreams()
			}()
			Eventually(conn.ReceivedSettings()).Should(BeClosed())
			Expect(conn.Settings().EnableDatagram).To(BeTrue())
			Expect(conn.Settings().EnableExtendedConnect).To(BeTrue())
			Expect(conn.Settings().Other).To(HaveKeyWithValue(uint64(1337), uint64(42)))
			Eventually(done).Should(BeClosed())
		})

		It("rejects duplicate control streams", func() {
			qconn := mockquic.NewMockEarlyConnection(mockCtrl)
			conn := newConnection(
				qconn,
				false,
				nil,
				protocol.PerspectiveServer,
				utils.DefaultLogger,
			)
			b := quicvarint.Append(nil, streamTypeControlStream)
			b = (&settingsFrame{}).Append(b)
			r1 := bytes.NewReader(b)
			controlStr1 := mockquic.NewMockStream(mockCtrl)
			controlStr1.EXPECT().Read(gomock.Any()).DoAndReturn(r1.Read).AnyTimes()
			r2 := bytes.NewReader(b)
			controlStr2 := mockquic.NewMockStream(mockCtrl)
			controlStr2.EXPECT().Read(gomock.Any()).DoAndReturn(r2.Read).AnyTimes()
			done := make(chan struct{})
			closed := make(chan struct{})
			qconn.EXPECT().CloseWithError(qerr.ApplicationErrorCode(ErrCodeStreamCreationError), "duplicate control stream").Do(func(qerr.ApplicationErrorCode, string) error {
				close(closed)
				return nil
			})
			qconn.EXPECT().AcceptUniStream(gomock.Any()).Return(controlStr1, nil)
			qconn.EXPECT().AcceptUniStream(gomock.Any()).Return(controlStr2, nil)
			qconn.EXPECT().AcceptUniStream(gomock.Any()).Return(nil, errors.New("test done"))
			go func() {
				defer GinkgoRecover()
				defer close(done)
				conn.HandleUnidirectionalStreams()
			}()
			Eventually(closed).Should(BeClosed())
			Eventually(done).Should(BeClosed())
		})

		for _, t := range []uint64{streamTypeQPACKEncoderStream, streamTypeQPACKDecoderStream} {
			streamType := t
			name := "encoder"
			if streamType == streamTypeQPACKDecoderStream {
				name = "decoder"
			}

			It(fmt.Sprintf("ignores the QPACK %s streams", name), func() {
				qconn := mockquic.NewMockEarlyConnection(mockCtrl)
				conn := newConnection(
					qconn,
					false,
					nil,
					protocol.PerspectiveClient,
					utils.DefaultLogger,
				)
				buf := bytes.NewBuffer(quicvarint.Append(nil, streamType))
				str := mockquic.NewMockStream(mockCtrl)
				str.EXPECT().Read(gomock.Any()).DoAndReturn(buf.Read).AnyTimes()
				qconn.EXPECT().AcceptUniStream(gomock.Any()).Return(str, nil)
				testDone := make(chan struct{})
				qconn.EXPECT().AcceptUniStream(gomock.Any()).DoAndReturn(func(context.Context) (quic.ReceiveStream, error) {
					<-testDone
					return nil, errors.New("test done")
				})
				time.Sleep(scaleDuration(20 * time.Millisecond)) // don't EXPECT any calls to str.CancelRead
				close(testDone)
				done := make(chan struct{})
				go func() {
					defer GinkgoRecover()
					defer close(done)
					conn.HandleUnidirectionalStreams()
				}()
				Eventually(done).Should(BeClosed())
			})

			It(fmt.Sprintf("rejects duplicate QPACK %s streams", name), func() {
				qconn := mockquic.NewMockEarlyConnection(mockCtrl)
				conn := newConnection(
					qconn,
					false,
					nil,
					protocol.PerspectiveClient,
					utils.DefaultLogger,
				)
				buf := bytes.NewBuffer(quicvarint.Append(nil, streamType))
				str1 := mockquic.NewMockStream(mockCtrl)
				str1.EXPECT().Read(gomock.Any()).DoAndReturn(buf.Read).AnyTimes()
				buf2 := bytes.NewBuffer(quicvarint.Append(nil, streamType))
				str2 := mockquic.NewMockStream(mockCtrl)
				str2.EXPECT().Read(gomock.Any()).DoAndReturn(buf2.Read).AnyTimes()
				qconn.EXPECT().AcceptUniStream(gomock.Any()).Return(str1, nil)
				qconn.EXPECT().AcceptUniStream(gomock.Any()).Return(str2, nil)
				testDone := make(chan struct{})
				qconn.EXPECT().AcceptUniStream(gomock.Any()).DoAndReturn(func(context.Context) (quic.ReceiveStream, error) {
					<-testDone
					return nil, errors.New("test done")
				})
				qconn.EXPECT().CloseWithError(qerr.ApplicationErrorCode(ErrCodeStreamCreationError), gomock.Any()).Do(func(qerr.ApplicationErrorCode, string) error {
					close(testDone)
					return nil
				})
				done := make(chan struct{})
				go func() {
					defer GinkgoRecover()
					defer close(done)
					conn.HandleUnidirectionalStreams()
				}()
				Eventually(done).Should(BeClosed())
			})
		}

		It("resets streams other than the control stream and the QPACK streams", func() {
			qconn := mockquic.NewMockEarlyConnection(mockCtrl)
			conn := newConnection(
				qconn,
				false,
				nil,
				protocol.PerspectiveServer,
				utils.DefaultLogger,
			)
			buf := bytes.NewBuffer(quicvarint.Append(nil, 0x1337))
			str := mockquic.NewMockStream(mockCtrl)
			str.EXPECT().Read(gomock.Any()).DoAndReturn(buf.Read).AnyTimes()
			reset := make(chan struct{})
			str.EXPECT().CancelRead(quic.StreamErrorCode(ErrCodeStreamCreationError)).Do(func(quic.StreamErrorCode) { close(reset) })
			qconn.EXPECT().AcceptUniStream(gomock.Any()).Return(str, nil)
			qconn.EXPECT().AcceptUniStream(gomock.Any()).Return(nil, errors.New("test done"))
			done := make(chan struct{})
			go func() {
				defer GinkgoRecover()
				defer close(done)
				conn.HandleUnidirectionalStreams()
			}()
			Eventually(done).Should(BeClosed())
			Eventually(reset).Should(BeClosed())
		})

		It("errors when the first frame on the control stream is not a SETTINGS frame", func() {
			qconn := mockquic.NewMockEarlyConnection(mockCtrl)
			conn := newConnection(
				qconn,
				false,
				nil,
				protocol.PerspectiveServer,
				utils.DefaultLogger,
			)
			b := quicvarint.Append(nil, streamTypeControlStream)
			b = (&dataFrame{}).Append(b)
			r := bytes.NewReader(b)
			controlStr := mockquic.NewMockStream(mockCtrl)
			controlStr.EXPECT().Read(gomock.Any()).DoAndReturn(r.Read).AnyTimes()
			qconn.EXPECT().AcceptUniStream(gomock.Any()).Return(controlStr, nil)
			qconn.EXPECT().AcceptUniStream(gomock.Any()).Return(nil, errors.New("test done"))
			closed := make(chan struct{})
			qconn.EXPECT().CloseWithError(quic.ApplicationErrorCode(ErrCodeMissingSettings), gomock.Any()).Do(func(quic.ApplicationErrorCode, string) error {
				close(closed)
				return nil
			})
			done := make(chan struct{})
			go func() {
				defer GinkgoRecover()
				defer close(done)
				conn.HandleUnidirectionalStreams()
			}()
			Eventually(done).Should(BeClosed())
			Eventually(closed).Should(BeClosed())
		})

		It("errors when parsing the frame on the control stream fails", func() {
			qconn := mockquic.NewMockEarlyConnection(mockCtrl)
			conn := newConnection(
				qconn,
				false,
				nil,
				protocol.PerspectiveServer,
				utils.DefaultLogger,
			)
			b := quicvarint.Append(nil, streamTypeControlStream)
			b = (&settingsFrame{}).Append(b)
			r := bytes.NewReader(b[:len(b)-1])
			controlStr := mockquic.NewMockStream(mockCtrl)
			controlStr.EXPECT().Read(gomock.Any()).DoAndReturn(r.Read).AnyTimes()
			qconn.EXPECT().AcceptUniStream(gomock.Any()).Return(controlStr, nil)
			qconn.EXPECT().AcceptUniStream(gomock.Any()).Return(nil, errors.New("test done"))
			closed := make(chan struct{})
			qconn.EXPECT().CloseWithError(quic.ApplicationErrorCode(ErrCodeFrameError), gomock.Any()).Do(func(code quic.ApplicationErrorCode, _ string) error {
				close(closed)
				return nil
			})
			done := make(chan struct{})
			go func() {
				defer GinkgoRecover()
				defer close(done)
				conn.HandleUnidirectionalStreams()
			}()
			Eventually(done).Should(BeClosed())
			Eventually(closed).Should(BeClosed())
		})

		for _, pers := range []protocol.Perspective{protocol.PerspectiveServer, protocol.PerspectiveClient} {
			pers := pers
			expectedErr := ErrCodeIDError
			if pers == protocol.PerspectiveClient {
				expectedErr = ErrCodeStreamCreationError
			}

			It(fmt.Sprintf("errors when parsing the %s opens a push stream", pers), func() {
				qconn := mockquic.NewMockEarlyConnection(mockCtrl)
				conn := newConnection(
					qconn,
					false,
					nil,
					pers.Opposite(),
					utils.DefaultLogger,
				)
				buf := bytes.NewBuffer(quicvarint.Append(nil, streamTypePushStream))
				controlStr := mockquic.NewMockStream(mockCtrl)
				controlStr.EXPECT().Read(gomock.Any()).DoAndReturn(buf.Read).AnyTimes()
				qconn.EXPECT().AcceptUniStream(gomock.Any()).Return(controlStr, nil)
				qconn.EXPECT().AcceptUniStream(gomock.Any()).Return(nil, errors.New("test done"))
				closed := make(chan struct{})
				qconn.EXPECT().CloseWithError(quic.ApplicationErrorCode(expectedErr), gomock.Any()).Do(func(quic.ApplicationErrorCode, string) error {
					close(closed)
					return nil
				})
				done := make(chan struct{})
				go func() {
					defer GinkgoRecover()
					defer close(done)
					conn.HandleUnidirectionalStreams()
				}()
				Eventually(done).Should(BeClosed())
				Eventually(closed).Should(BeClosed())
			})
		}

		It("errors when the server advertises datagram support (and we enabled support for it)", func() {
			qconn := mockquic.NewMockEarlyConnection(mockCtrl)
			conn := newConnection(
				qconn,
				true,
				nil,
				protocol.PerspectiveClient,
				utils.DefaultLogger,
			)
			b := quicvarint.Append(nil, streamTypeControlStream)
			b = (&settingsFrame{Datagram: true}).Append(b)
			r := bytes.NewReader(b)
			controlStr := mockquic.NewMockStream(mockCtrl)
			controlStr.EXPECT().Read(gomock.Any()).DoAndReturn(r.Read).AnyTimes()
			qconn.EXPECT().AcceptUniStream(gomock.Any()).Return(controlStr, nil)
			qconn.EXPECT().AcceptUniStream(gomock.Any()).Return(nil, errors.New("test done"))
			qconn.EXPECT().ConnectionState().Return(quic.ConnectionState{SupportsDatagrams: false})
			closed := make(chan struct{})
			qconn.EXPECT().CloseWithError(quic.ApplicationErrorCode(ErrCodeSettingsError), "missing QUIC Datagram support").Do(func(quic.ApplicationErrorCode, string) error {
				close(closed)
				return nil
			})
			done := make(chan struct{})
			go func() {
				defer GinkgoRecover()
				defer close(done)
				conn.HandleUnidirectionalStreams()
			}()
			Eventually(done).Should(BeClosed())
			Eventually(closed).Should(BeClosed())
		})
	})
})
