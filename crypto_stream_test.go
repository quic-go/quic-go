package quic

import (
	"fmt"
	mrand "math/rand/v2"
	"slices"
	"testing"

	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/qerr"
	"github.com/quic-go/quic-go/internal/wire"

	"github.com/stretchr/testify/require"
)

func TestCryptoStreamDataAssembly(t *testing.T) {
	str := newCryptoStream()
	require.NoError(t, str.HandleCryptoFrame(&wire.CryptoFrame{Data: []byte("bar"), Offset: 3}))
	require.NoError(t, str.HandleCryptoFrame(&wire.CryptoFrame{Data: []byte("foo")}))
	// receive a retransmission
	require.NoError(t, str.HandleCryptoFrame(&wire.CryptoFrame{Data: []byte("bar"), Offset: 3}))

	var data []byte
	for {
		b := str.GetCryptoData()
		if b == nil {
			break
		}
		data = append(data, b...)
	}
	require.Equal(t, []byte("foobar"), data)
}

func TestCryptoStreamMaxOffset(t *testing.T) {
	str := newCryptoStream()
	require.NoError(t, str.HandleCryptoFrame(&wire.CryptoFrame{
		Offset: protocol.MaxCryptoStreamOffset - 5,
		Data:   []byte("foo"),
	}))
	require.ErrorIs(t,
		str.HandleCryptoFrame(&wire.CryptoFrame{
			Offset: protocol.MaxCryptoStreamOffset - 2,
			Data:   []byte("bar"),
		}),
		&qerr.TransportError{ErrorCode: qerr.CryptoBufferExceeded},
	)
}

func TestCryptoStreamFinishWithQueuedData(t *testing.T) {
	t.Run("with data at current offset", func(t *testing.T) {
		str := newCryptoStream()
		require.NoError(t, str.HandleCryptoFrame(&wire.CryptoFrame{Data: []byte("foo")}))
		require.Equal(t, []byte("foo"), str.GetCryptoData())
		require.NoError(t, str.HandleCryptoFrame(&wire.CryptoFrame{Data: []byte("bar"), Offset: 3}))
		require.ErrorIs(t, str.Finish(), &qerr.TransportError{ErrorCode: qerr.ProtocolViolation})
	})

	t.Run("with data at a higher offset", func(t *testing.T) {
		str := newCryptoStream()
		require.NoError(t, str.HandleCryptoFrame(&wire.CryptoFrame{Data: []byte("foobar"), Offset: 20}))
		require.ErrorIs(t, str.Finish(), &qerr.TransportError{ErrorCode: qerr.ProtocolViolation})
	})
}

func TestCryptoStreamReceiveDataAfterFinish(t *testing.T) {
	str := newCryptoStream()
	require.NoError(t, str.HandleCryptoFrame(&wire.CryptoFrame{Data: []byte("foobar")}))
	require.Equal(t, []byte("foobar"), str.GetCryptoData())
	require.NoError(t, str.Finish())
	// receiving a retransmission is ok
	require.NoError(t, str.HandleCryptoFrame(&wire.CryptoFrame{Data: []byte("bar"), Offset: 3}))
	// but receiving new data is not
	require.ErrorIs(t,
		str.HandleCryptoFrame(&wire.CryptoFrame{Data: []byte("baz"), Offset: 4}),
		&qerr.TransportError{ErrorCode: qerr.ProtocolViolation},
	)
}

func expectedCryptoFrameLen(offset protocol.ByteCount) protocol.ByteCount {
	f := &wire.CryptoFrame{Offset: offset}
	return f.Length(protocol.Version1)
}

func TestCryptoStreamWrite(t *testing.T) {
	str := newCryptoStream()

	require.False(t, str.HasData())
	_, err := str.Write([]byte("foo"))
	require.NoError(t, err)
	require.True(t, str.HasData())
	_, err = str.Write([]byte("bar"))
	require.NoError(t, err)
	_, err = str.Write([]byte("baz"))
	require.NoError(t, err)
	require.True(t, str.HasData())

	for i := range expectedCryptoFrameLen(0) {
		require.Nil(t, str.PopCryptoFrame(i))
	}

	f := str.PopCryptoFrame(expectedCryptoFrameLen(0) + 1)
	require.Equal(t, &wire.CryptoFrame{Data: []byte("f")}, f)
	require.True(t, str.HasData())
	f = str.PopCryptoFrame(expectedCryptoFrameLen(1) + 3)
	// the three write calls were coalesced into a single frame
	require.Equal(t, &wire.CryptoFrame{Offset: 1, Data: []byte("oob")}, f)
	f = str.PopCryptoFrame(protocol.MaxByteCount)
	require.Equal(t, &wire.CryptoFrame{Offset: 4, Data: []byte("arbaz")}, f)
	require.False(t, str.HasData())
}

func TestInitialCryptoStreamServer(t *testing.T) {
	str := newInitialCryptoStream(false)
	_, err := str.Write([]byte("foobar"))
	require.NoError(t, err)

	f := str.PopCryptoFrame(expectedCryptoFrameLen(0) + 3)
	require.Equal(t, &wire.CryptoFrame{Offset: 0, Data: []byte("foo")}, f)
	require.True(t, str.HasData())

	// append another CRYPTO frame to the existing slice
	f = str.PopCryptoFrame(expectedCryptoFrameLen(3) + 3)
	require.Equal(t, &wire.CryptoFrame{Offset: 3, Data: []byte("bar")}, f)
	require.False(t, str.HasData())
}

func reassembleCryptoData(t *testing.T, segments map[protocol.ByteCount][]byte) []byte {
	t.Helper()

	var reassembled []byte
	var offset protocol.ByteCount
	for len(segments) > 0 {
		b, ok := segments[offset]
		if !ok {
			break
		}
		reassembled = append(reassembled, b...)
		delete(segments, offset)
		offset = protocol.ByteCount(len(reassembled))
	}
	require.Empty(t, segments)
	return reassembled
}

func TestInitialCryptoStreamClient(t *testing.T) {
	str := newInitialCryptoStream(true)
	_, err := str.Write(clientHello)
	require.NoError(t, err)
	require.True(t, str.HasData())
	_, err = str.Write([]byte("foobar"))
	require.NoError(t, err)

	segments := make(map[protocol.ByteCount][]byte)

	f1 := str.PopCryptoFrame(protocol.MaxByteCount)
	require.NotNil(t, f1)
	segments[f1.Offset] = f1.Data
	require.True(t, str.HasData())

	f2 := str.PopCryptoFrame(protocol.MaxByteCount)
	require.NotNil(t, f2)
	require.NotContains(t, segments, f2.Offset)
	segments[f2.Offset] = f2.Data
	require.True(t, str.HasData())

	f3 := str.PopCryptoFrame(protocol.MaxByteCount)
	require.NotNil(t, f2)
	require.NotContains(t, segments, f3.Offset)
	segments[f3.Offset] = f3.Data
	require.True(t, str.HasData())

	f4 := str.PopCryptoFrame(protocol.MaxByteCount)
	require.NotNil(t, f4)
	require.NotContains(t, segments, f4.Offset)
	segments[f4.Offset] = f4.Data
	require.Equal(t, []byte("foobar"), f4.Data)
	require.False(t, str.HasData())

	reassembled := reassembleCryptoData(t, segments)
	require.Equal(t, append(clientHello, []byte("foobar")...), reassembled)
}

func TestInitialCryptoStreamClientRandomizedSizes(t *testing.T) {
	for i := range 5 {
		t.Run(fmt.Sprintf("run %d", i), func(t *testing.T) {
			testInitialCryptoStreamClientRandomizedSizes(t)
		})
	}
}

func testInitialCryptoStreamClientRandomizedSizes(t *testing.T) {
	str := newInitialCryptoStream(true)

	b := slices.Clone(clientHello)
	for len(b) > 0 {
		n := min(len(b), mrand.IntN(2*len(b)))
		_, err := str.Write(b[:n])
		require.NoError(t, err)
		b = b[n:]
	}

	require.True(t, str.HasData())
	_, err := str.Write([]byte("foobar"))
	require.NoError(t, err)

	segments := make(map[protocol.ByteCount][]byte)

	var frames []*wire.CryptoFrame
	for str.HasData() {
		maxSize := protocol.ByteCount(mrand.IntN(128) + 1)
		f := str.PopCryptoFrame(maxSize)
		if f == nil {
			continue
		}
		frames = append(frames, f)
		require.LessOrEqual(t, f.Length(protocol.Version1), maxSize)
	}
	t.Logf("received %d frames", len(frames))

	for _, f := range frames {
		// require.NotContains(t, cf.Data, []byte("google.com"))
		t.Logf("received frame (%d bytes) at offset %d", len(f.Data), f.Offset)
		segments[f.Offset] = f.Data
	}

	reassembled := reassembleCryptoData(t, segments)
	require.Equal(t, append(clientHello, []byte("foobar")...), reassembled)
	// require.Contains(t, reassembled, []byte("google.com"))
}
