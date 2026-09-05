package quic

import (
	"fmt"
	"net"
	"net/netip"
	"os"
	"runtime"
	"syscall"
	"testing"
	"testing/synctest"
	"time"

	"github.com/quic-go/quic-go/internal/protocol"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

func getPacketWithContents(b []byte) *packetBuffer {
	buf := getPacketBuffer()
	buf.Data = buf.Data[:len(b)]
	copy(buf.Data, b)
	return buf
}

func TestSendQueueSendOnePacket(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		mockCtrl := gomock.NewController(t)
		c := NewMockSendConn(mockCtrl)
		q := newSendQueue(c, nil)

		written := make(chan struct{})
		c.EXPECT().Write([]byte("foobar"), uint16(10), protocol.ECT1).Do(
			func([]byte, uint16, protocol.ECN) error { close(written); return nil },
		)

		done := make(chan struct{})
		go func() {
			q.Run()
			close(done)
		}()

		q.Send(getPacketWithContents([]byte("foobar")), 10, protocol.ECT1)
		synctest.Wait()

		select {
		case <-written:
		default:
			t.Fatal("write should have returned")
		}

		q.Close()
		synctest.Wait()

		select {
		case <-done:
		default:
			t.Fatal("Run should have returned")
		}
	})
}

func TestSendQueueBlocking(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		mockCtrl := gomock.NewController(t)
		c := NewMockSendConn(mockCtrl)
		q := newSendQueue(c, nil)

		blockWrite := make(chan struct{})
		written := make(chan struct{}, 1)
		c.EXPECT().Write(gomock.Any(), gomock.Any(), gomock.Any()).Do(
			func([]byte, uint16, protocol.ECN) error {
				select {
				case written <- struct{}{}:
				default:
				}
				<-blockWrite
				return nil
			},
		).AnyTimes()

		done := make(chan struct{})
		go func() {
			q.Run()
			close(done)
		}()

		// +1, since one packet will be queued in the Write call
		for i := range sendQueueCapacity + 1 {
			require.False(t, q.WouldBlock())
			q.Send(getPacketWithContents([]byte("foobar")), 10, protocol.ECT1)
			// make sure that the first packet is actually enqueued in the Write call
			if i == 0 {
				select {
				case <-written:
				case <-time.After(time.Second):
					t.Fatal("timeout")
				}
			}
		}
		require.True(t, q.WouldBlock())
		select {
		case <-q.Available():
			t.Fatal("should not be available")
		default:
		}
		require.Panics(t, func() { q.Send(getPacketWithContents([]byte("foobar")), 10, protocol.ECT1) })

		// allow one packet to be sent
		blockWrite <- struct{}{}
		select {
		case <-written:
		case <-time.After(time.Second):
			t.Fatal("timeout")
		}
		select {
		case <-q.Available():
			require.False(t, q.WouldBlock())
		case <-time.After(time.Second):
			t.Fatal("timeout")
		}

		// when calling Close, all packets are first sent out
		closed := make(chan struct{})
		go func() {
			q.Close()
			close(closed)
		}()

		synctest.Wait()

		select {
		case <-closed:
			t.Fatal("Close should have blocked")
		default:
		}

		for range sendQueueCapacity {
			blockWrite <- struct{}{}
		}
		synctest.Wait()

		select {
		case <-closed:
		default:
			t.Fatal("Close should have returned")
		}
		select {
		case <-done:
		default:
			t.Fatal("Run should have returned")
		}
	})
}

func TestSendQueueWriteError(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		mockCtrl := gomock.NewController(t)
		c := NewMockSendConn(mockCtrl)
		q := newSendQueue(c, nil)

		c.EXPECT().Write(gomock.Any(), gomock.Any(), gomock.Any()).Return(assert.AnError)
		q.Send(getPacketWithContents([]byte("foobar")), 6, protocol.ECNNon)

		errChan := make(chan error, 1)
		go func() { errChan <- q.Run() }()

		synctest.Wait()

		select {
		case err := <-errChan:
			require.ErrorIs(t, err, assert.AnError)
		default:
			t.Fatal("Run should have returned")
		}

		// further calls to Send should not block
		sent := make(chan struct{})
		go func() {
			defer close(sent)
			for range 2 * sendQueueCapacity {
				q.Send(getPacketWithContents([]byte("raboof")), 6, protocol.ECNNon)
			}
		}()

		synctest.Wait()

		select {
		case <-sent:
		default:
			t.Fatal("Send should have returned")
		}
	})
}

func TestSendQueueSendProbe(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	c := NewMockSendConn(mockCtrl)
	q := newSendQueue(c, nil)

	addr := &net.UDPAddr{IP: net.IPv4(42, 42, 42, 42), Port: 42}
	localAddr := netip.MustParseAddr("43.43.43.43")
	c.EXPECT().WriteTo([]byte("foobar"), addr, packetInfo{
		addr: localAddr,
	})
	q.SendProbe(getPacketWithContents([]byte("foobar")), addr, packetInfo{
		addr: localAddr,
	})
}

func TestSendQueueSendMessageTooLarge(t *testing.T) {
	err := syscall.EMSGSIZE
	if runtime.GOOS == "windows" {
		err = syscall.Errno(10040) // WSAEMSGSIZE
	}
	if !isSendMsgSizeErr(err) {
		t.Skip("send message size errors are not recognized on this platform")
	}
	for _, size := range []int{protocol.MinInitialPacketSize, protocol.InitialPacketSize} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				ctrl := gomock.NewController(t)
				conn := NewMockSendConn(ctrl)
				notify := make(chan struct{}, 1)
				q := newSendQueue(conn, notify)
				conn.EXPECT().Write(gomock.Any(), uint16(0), protocol.ECNNon).Return(
					&net.OpError{Op: "write", Err: &os.SyscallError{Syscall: "sendmsg", Err: err}},
				).Times(2 * sendQueueCapacity)
				done := make(chan error, 1)
				go func() { done <- q.Run() }()
				// An unread notification must not block further writes or Close.
				for range 2 * sendQueueCapacity {
					q.Send(getPacketWithContents(make([]byte, size)), 0, protocol.ECNNon)
					synctest.Wait()
				}
				q.Close()
				require.NoError(t, <-done)
				if size > protocol.MinInitialPacketSize {
					require.Len(t, notify, 1)
				} else {
					require.Empty(t, notify)
				}
			})
		})
	}
}
