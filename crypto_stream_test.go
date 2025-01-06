package quic

import (
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

func TestCryptoStreamWrite(t *testing.T) {
	expectedCryptoFrameLen := func(offset protocol.ByteCount) protocol.ByteCount {
		f := &wire.CryptoFrame{Offset: offset}
		return f.Length(protocol.Version1)
	}

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

	f := str.PopCryptoFrame(expectedCryptoFrameLen(0) + 3)
	require.Equal(t, &wire.CryptoFrame{Data: []byte("foo")}, f)
	require.True(t, str.HasData())
	f = str.PopCryptoFrame(protocol.MaxByteCount)
	// the two write calls were coalesced into a single frame
	require.Equal(t, &wire.CryptoFrame{Offset: 3, Data: []byte("barbaz")}, f)
	require.False(t, str.HasData())
}
