package quic

import (
	"crypto/rand"
	"testing"
	"time"

	"github.com/quic-go/quic-go/internal/handshake"
	"github.com/quic-go/quic-go/internal/mocks"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/qerr"
	"github.com/quic-go/quic-go/internal/wire"

	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

type decryptResult struct {
	decrypted []byte
	err       error
}

func TestUnpackLongHeaderPacket(t *testing.T) {
	b := []byte("decrypted")

	t.Run("Initial", func(t *testing.T) {
		testUnpackLongHeaderPacket(t, protocol.EncryptionInitial, false, decryptResult{decrypted: b}, nil)
	})
	t.Run("Handshake", func(t *testing.T) {
		testUnpackLongHeaderPacket(t, protocol.EncryptionHandshake, false, decryptResult{decrypted: b}, nil)
	})
	t.Run("0-RTT", func(t *testing.T) {
		testUnpackLongHeaderPacket(t, protocol.Encryption0RTT, false, decryptResult{decrypted: b}, nil)
	})
}

func TestUnpackLongHeaderIncorrectReservedBits(t *testing.T) {
	t.Run("decryption fails", func(t *testing.T) {
		testUnpackLongHeaderIncorrectReservedBits(t, true)
	})
	t.Run("decryption succeeds", func(t *testing.T) {
		testUnpackLongHeaderIncorrectReservedBits(t, false)
	})
}

// Even if the reserved bits are wrong, we still need to continue processing the header.
// This helps prevent a timing side-channel attack, see section 9.5 of RFC 9001.
// We should only return a ErrInvalidReservedBits error if the decryption succeeds,
// as this shows that the peer actually sent an invalid packet.
// However, if decryption fails, this packet is likely injected by an attacker,
// and we should treat it as any other undecryptable packet.
func testUnpackLongHeaderIncorrectReservedBits(t *testing.T, decryptionSucceeds bool) {
	decrypted := []byte("decrypted")
	expectedErr := wire.ErrInvalidReservedBits
	decryptResult := decryptResult{decrypted: decrypted}
	if !decryptionSucceeds {
		decryptResult.err = handshake.ErrDecryptionFailed
		expectedErr = handshake.ErrDecryptionFailed
	}

	t.Run("Initial", func(t *testing.T) {
		testUnpackLongHeaderPacket(t, protocol.EncryptionInitial, true, decryptResult, expectedErr)
	})
	t.Run("Handshake", func(t *testing.T) {
		testUnpackLongHeaderPacket(t, protocol.EncryptionHandshake, true, decryptResult, expectedErr)
	})
	t.Run("0-RTT", func(t *testing.T) {
		testUnpackLongHeaderPacket(t, protocol.Encryption0RTT, true, decryptResult, expectedErr)
	})
}

func TestUnpackLongHeaderEmptyPayload(t *testing.T) {
	expectedErr := &qerr.TransportError{ErrorCode: qerr.ProtocolViolation}

	t.Run("Initial", func(t *testing.T) {
		testUnpackLongHeaderPacket(t, protocol.EncryptionInitial, false, decryptResult{}, expectedErr)
	})

	t.Run("Handshake", func(t *testing.T) {
		testUnpackLongHeaderPacket(t, protocol.EncryptionHandshake, false, decryptResult{}, expectedErr)
	})

	t.Run("0-RTT", func(t *testing.T) {
		testUnpackLongHeaderPacket(t, protocol.Encryption0RTT, false, decryptResult{}, expectedErr)
	})
}

func testUnpackLongHeaderPacket(t *testing.T,
	encLevel protocol.EncryptionLevel,
	incorrectReservedBits bool,
	decryptResult decryptResult,
	expectedErr error,
) {
	mockCtrl := gomock.NewController(t)
	cs := mocks.NewMockCryptoSetup(mockCtrl)
	unpacker := newPacketUnpacker(cs, 4)

	var packetType protocol.PacketType
	switch encLevel {
	case protocol.EncryptionInitial:
		packetType = protocol.PacketTypeInitial
	case protocol.EncryptionHandshake:
		packetType = protocol.PacketTypeHandshake
	case protocol.Encryption0RTT:
		packetType = protocol.PacketType0RTT
	}

	payload := []byte("Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.")
	extHdr := &wire.ExtendedHeader{
		Header: wire.Header{
			Type:             packetType,
			Length:           protocol.ByteCount(3 + len(payload)), // packet number len + payload
			DestConnectionID: protocol.ParseConnectionID([]byte{0xde, 0xad, 0xbe, 0xef}),
			Version:          protocol.Version1,
		},
		PacketNumber:    2,
		PacketNumberLen: 3,
	}
	hdrRaw, err := extHdr.Append(nil, protocol.Version1)
	require.NoError(t, err)
	if incorrectReservedBits {
		hdrRaw[0] |= 0xc
	}
	data := append(hdrRaw, payload...)
	hdr, _, _, err := wire.ParsePacket(data)
	require.NoError(t, err)

	opener := mocks.NewMockLongHeaderOpener(mockCtrl)
	var calls []any
	switch encLevel {
	case protocol.EncryptionInitial:
		calls = append(calls, cs.EXPECT().GetInitialOpener().Return(opener, nil))
	case protocol.EncryptionHandshake:
		calls = append(calls, cs.EXPECT().GetHandshakeOpener().Return(opener, nil))
	case protocol.Encryption0RTT:
		calls = append(calls, cs.EXPECT().Get0RTTOpener().Return(opener, nil))
	}
	calls = append(calls, []any{
		opener.EXPECT().DecryptHeader(gomock.Any(), gomock.Any(), gomock.Any()),
		opener.EXPECT().DecodePacketNumber(protocol.PacketNumber(2), protocol.PacketNumberLen3).Return(protocol.PacketNumber(1234)),
		opener.EXPECT().Open(gomock.Any(), payload, protocol.PacketNumber(1234), hdrRaw).Return(
			decryptResult.decrypted, decryptResult.err,
		),
	}...)
	gomock.InOrder(calls...)

	packet, err := unpacker.UnpackLongHeader(hdr, data)
	if expectedErr != nil {
		require.ErrorIs(t, err, expectedErr)
		return
	}
	require.NoError(t, err)
	require.Equal(t, encLevel, packet.encryptionLevel)
	require.Equal(t, decryptResult.decrypted, packet.data)
}

func TestUnpackShortHeaderPacket(t *testing.T) {
	testUnpackShortHeaderPacket(t, false, decryptResult{decrypted: []byte("decrypted")}, nil)
}

func TestUnpackShortHeaderEmptyPayload(t *testing.T) {
	testUnpackShortHeaderPacket(t, false, decryptResult{}, &qerr.TransportError{ErrorCode: qerr.ProtocolViolation})
}

// Even if the reserved bits are wrong, we still need to continue processing the header.
// This helps prevent a timing side-channel attack, see section 9.5 of RFC 9001.
// We should only return a ErrInvalidReservedBits error if the decryption succeeds,
// as this shows that the peer actually sent an invalid packet.
// However, if decryption fails, this packet is likely injected by an attacker,
// and we should treat it as any other undecryptable packet.
func TestUnpackShortHeaderIncorrectReservedBits(t *testing.T) {
	t.Run("decryption fails", func(t *testing.T) {
		testUnpackShortHeaderPacket(t,
			true,
			decryptResult{err: handshake.ErrDecryptionFailed},
			handshake.ErrDecryptionFailed,
		)
	})

	t.Run("decryption succeeds", func(t *testing.T) {
		testUnpackShortHeaderPacket(t,
			true,
			decryptResult{decrypted: []byte("decrypted")},
			wire.ErrInvalidReservedBits,
		)
	})
}

func testUnpackShortHeaderPacket(t *testing.T, incorrectReservedBits bool, decryptResult decryptResult, expectedErr error) {
	mockCtrl := gomock.NewController(t)
	connID := protocol.ParseConnectionID([]byte{1, 2, 3, 4, 5})
	cs := mocks.NewMockCryptoSetup(mockCtrl)
	unpacker := newPacketUnpacker(cs, connID.Len())
	payload := []byte("Lorem ipsum dolor sit amet")

	hdrRaw, err := wire.AppendShortHeader(
		nil,
		connID,
		0x1337,
		protocol.PacketNumberLen3,
		protocol.KeyPhaseOne,
	)
	require.NoError(t, err)
	if incorrectReservedBits {
		hdrRaw[0] |= 0x18
	}
	opener := mocks.NewMockShortHeaderOpener(mockCtrl)
	opener.EXPECT().DecryptHeader(gomock.Any(), gomock.Any(), gomock.Any())
	cs.EXPECT().Get1RTTOpener().Return(opener, nil)
	opener.EXPECT().DecodePacketNumber(gomock.Any(), gomock.Any()).Return(protocol.PacketNumber(1234))
	opener.EXPECT().Open(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(
		decryptResult.decrypted, decryptResult.err,
	)
	pn, pnLen, kp, data, err := unpacker.UnpackShortHeader(time.Now(), append(hdrRaw, payload...))
	if expectedErr != nil {
		require.ErrorIs(t, err, expectedErr)
		return
	}
	require.NoError(t, err)
	require.Equal(t, decryptResult.decrypted, data)
	require.Equal(t, protocol.PacketNumber(1234), pn)
	require.Equal(t, protocol.PacketNumberLen3, pnLen)
	require.Equal(t, protocol.KeyPhaseOne, kp)
}

func TestUnpackHeaderSampleLongHeader(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	cs := mocks.NewMockCryptoSetup(mockCtrl)
	unpacker := newPacketUnpacker(cs, 4)

	extHdr := &wire.ExtendedHeader{
		Header: wire.Header{
			Type:             protocol.PacketTypeHandshake,
			DestConnectionID: protocol.ParseConnectionID([]byte{0xde, 0xad, 0xbe, 0xef}),
			Version:          protocol.Version1,
		},
		PacketNumber:    1337,
		PacketNumberLen: protocol.PacketNumberLen2,
	}
	data, err := extHdr.Append(nil, protocol.Version1)
	require.NoError(t, err)
	b := make([]byte, 2+16) // 2 bytes to fill up the packet number, 16 bytes for the sample
	rand.Read(b)
	data = append(data, b...)
	hdr, _, _, err := wire.ParsePacket(data)
	require.NoError(t, err)

	t.Run("too short", func(t *testing.T) {
		cs.EXPECT().GetHandshakeOpener().Return(mocks.NewMockLongHeaderOpener(mockCtrl), nil)
		_, err = unpacker.UnpackLongHeader(hdr, data[:len(data)-1])
		require.IsType(t, &headerParseError{}, err)
		require.ErrorContains(t, err, "Packet too small. Expected at least 20 bytes after the header, got 19")
	})

	t.Run("minimal size", func(t *testing.T) {
		opener := mocks.NewMockLongHeaderOpener(mockCtrl)
		cs.EXPECT().GetHandshakeOpener().Return(opener, nil)
		opener.EXPECT().DecryptHeader(b[len(b)-16:], gomock.Any(), gomock.Any())
		opener.EXPECT().DecodePacketNumber(gomock.Any(), gomock.Any()).Return(protocol.PacketNumber(1337))
		opener.EXPECT().Open(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return([]byte("decrypted"), nil)
		_, err = unpacker.UnpackLongHeader(hdr, data)
		require.NoError(t, err)
	})
}

func TestUnpackHeaderSampleShortHeader(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	cs := mocks.NewMockCryptoSetup(mockCtrl)
	unpacker := newPacketUnpacker(cs, 4)

	data, err := wire.AppendShortHeader(
		nil,
		protocol.ParseConnectionID([]byte{0xde, 0xad, 0xbe, 0xef}),
		1337,
		protocol.PacketNumberLen2,
		protocol.KeyPhaseOne,
	)
	require.NoError(t, err)
	b := make([]byte, 2+16) // 2 bytes to fill up the packet number, 16 bytes for the sample
	rand.Read(b)
	data = append(data, b...)

	t.Run("too short", func(t *testing.T) {
		cs.EXPECT().Get1RTTOpener().Return(mocks.NewMockShortHeaderOpener(mockCtrl), nil)
		_, _, _, _, err = unpacker.UnpackShortHeader(time.Now(), data[:len(data)-1])
		require.IsType(t, &headerParseError{}, err)
		require.ErrorContains(t, err, "packet too small, expected at least 20 bytes after the header, got 19")
	})

	t.Run("minimal size", func(t *testing.T) {
		opener := mocks.NewMockShortHeaderOpener(mockCtrl)
		cs.EXPECT().Get1RTTOpener().Return(opener, nil)
		opener.EXPECT().DecryptHeader(data[len(data)-16:], gomock.Any(), gomock.Any())
		opener.EXPECT().DecodePacketNumber(gomock.Any(), gomock.Any()).Return(protocol.PacketNumber(1337))
		opener.EXPECT().Open(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return([]byte("decrypted"), nil)
		_, _, _, _, err = unpacker.UnpackShortHeader(time.Now(), data)
		require.NoError(t, err)
	})
}

func TestUnpackErrors(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	cs := mocks.NewMockCryptoSetup(mockCtrl)
	unpacker := newPacketUnpacker(cs, 4)

	// opener not available
	cs.EXPECT().GetHandshakeOpener().Return(nil, handshake.ErrKeysNotYetAvailable)
	_, err := unpacker.UnpackLongHeader(&wire.Header{Type: protocol.PacketTypeHandshake}, []byte("foobar"))
	require.ErrorIs(t, err, handshake.ErrKeysNotYetAvailable)

	// opener returns error
	opener := mocks.NewMockLongHeaderOpener(mockCtrl)
	cs.EXPECT().GetHandshakeOpener().Return(opener, nil)
	opener.EXPECT().DecryptHeader(gomock.Any(), gomock.Any(), gomock.Any())
	opener.EXPECT().DecodePacketNumber(gomock.Any(), gomock.Any()).Return(protocol.PacketNumber(1234))
	opener.EXPECT().Open(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, &qerr.TransportError{ErrorCode: qerr.CryptoBufferExceeded})
	_, err = unpacker.UnpackLongHeader(&wire.Header{Type: protocol.PacketTypeHandshake}, make([]byte, 100))
	require.ErrorIs(t, err, &qerr.TransportError{ErrorCode: qerr.CryptoBufferExceeded})
}

func TestUnpackHeaderDecryption(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	cs := mocks.NewMockCryptoSetup(mockCtrl)
	unpacker := newPacketUnpacker(cs, 4)
	connID := protocol.ParseConnectionID([]byte{0xde, 0xad, 0xbe, 0xef})

	extHdr := &wire.ExtendedHeader{
		Header: wire.Header{
			Type:             protocol.PacketTypeHandshake,
			Length:           2, // packet number len
			DestConnectionID: connID,
			Version:          protocol.Version1,
		},
		PacketNumber:    0x1337,
		PacketNumberLen: protocol.PacketNumberLen2,
	}
	hdrRaw, err := extHdr.Append(nil, protocol.Version1)
	require.NoError(t, err)
	hdr, _, _, err := wire.ParsePacket(hdrRaw)
	require.NoError(t, err)

	origHdrRaw := append([]byte{}, hdrRaw...) // save a copy of the header
	firstHdrByte := hdrRaw[0]
	hdrRaw[0] ^= 0xff             // invert the first byte
	hdrRaw[len(hdrRaw)-2] ^= 0xff // invert the packet number
	hdrRaw[len(hdrRaw)-1] ^= 0xff // invert the packet number
	require.NotEqual(t, hdrRaw[0], firstHdrByte)

	opener := mocks.NewMockLongHeaderOpener(mockCtrl)
	cs.EXPECT().GetHandshakeOpener().Return(opener, nil)
	gomock.InOrder(
		// we're using a 2 byte packet number, so the sample starts at the 3rd payload byte
		opener.EXPECT().DecryptHeader(
			[]byte{3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18},
			&hdrRaw[0],
			append(hdrRaw[len(hdrRaw)-2:], []byte{1, 2}...)).Do(func(_ []byte, firstByte *byte, pnBytes []byte) {
			*firstByte ^= 0xff // invert the first byte back
			for i := range pnBytes {
				pnBytes[i] ^= 0xff // invert the packet number bytes
			}
		}),
		opener.EXPECT().DecodePacketNumber(protocol.PacketNumber(0x1337), protocol.PacketNumberLen2).Return(protocol.PacketNumber(0x7331)),
		opener.EXPECT().Open(gomock.Any(), gomock.Any(), protocol.PacketNumber(0x7331), origHdrRaw).Return([]byte{0}, nil),
	)

	data := hdrRaw
	for i := 1; i <= 100; i++ {
		data = append(data, uint8(i))
	}
	packet, err := unpacker.UnpackLongHeader(hdr, data)
	require.NoError(t, err)
	require.Equal(t, protocol.PacketNumber(0x7331), packet.hdr.PacketNumber)
}
