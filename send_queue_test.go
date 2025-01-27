package quic

import (
	"errors"
	"net"
	"testing"
	"time"

	"github.com/quic-go/quic-go/internal/protocol"
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
	mockCtrl := gomock.NewController(t)
	c := NewMockSendConn(mockCtrl)
	q := newSendQueue(c)

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

	select {
	case <-written:
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}

	q.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}
}

func TestSendQueueBlocking(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	c := NewMockSendConn(mockCtrl)
	q := newSendQueue(c)

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
	for i := 0; i < sendQueueCapacity+1; i++ {
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

	select {
	case <-closed:
		t.Fatal("Close should have blocked")
	case <-time.After(scaleDuration(10 * time.Millisecond)):
	}

	for i := 0; i < sendQueueCapacity; i++ {
		blockWrite <- struct{}{}
	}
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}
}

func TestSendQueueWriteError(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	c := NewMockSendConn(mockCtrl)
	q := newSendQueue(c)

	c.EXPECT().Write(gomock.Any(), gomock.Any(), gomock.Any()).Return(errors.New("test error"))
	q.Send(getPacketWithContents([]byte("foobar")), 6, protocol.ECNNon)

	errChan := make(chan error, 1)
	go func() { errChan <- q.Run() }()

	select {
	case err := <-errChan:
		require.EqualError(t, err, "test error")
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}

	// further calls to Send should not block
	sent := make(chan struct{})
	go func() {
		defer close(sent)
		for i := 0; i < 2*sendQueueCapacity; i++ {
			q.Send(getPacketWithContents([]byte("raboof")), 6, protocol.ECNNon)
		}
	}()

	select {
	case <-sent:
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}
}

func TestSendQueueSendProbe(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	c := NewMockSendConn(mockCtrl)
	q := newSendQueue(c)

	addr := &net.UDPAddr{IP: net.IPv4(42, 42, 42, 42), Port: 42}
	c.EXPECT().WriteTo([]byte("foobar"), addr)
	q.SendProbe(getPacketWithContents([]byte("foobar")), addr)
}
