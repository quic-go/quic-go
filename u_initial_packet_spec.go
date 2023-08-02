package quic

import (
	"bytes"
	"crypto/rand"
	"errors"

	"github.com/gaukas/clienthellod"
	"github.com/quic-go/quic-go/quicvarint"
)

type InitialPacketSpec struct {
	// SrcConnIDLength specifies how many bytes should the SrcConnID be
	SrcConnIDLength int

	// DestConnIDLength specifies how many bytes should the DestConnID be
	DestConnIDLength int

	// InitPacketNumberLength specifies how many bytes should the InitPacketNumber
	// be interpreted as. It is usually 1 or 2 bytes. If unset, UQUIC will use the
	// default algorithm to compute the length which is at least 2 bytes.
	InitPacketNumberLength PacketNumberLen

	// InitPacketNumber is the packet number of the first Initial packet. Following
	// Initial packets, if any, will increment the Packet Number accordingly.
	InitPacketNumber uint64 // [UQUIC]

	// TokenStore is used to store and retrieve tokens. If set, will override the
	// one set in the Config.
	TokenStore TokenStore

	// If ClientTokenLength is set when TokenStore is not set, a dummy TokenStore
	// will be created to randomly generate tokens of the specified length for
	// Pop() calls with any key and silently drop any Put() calls.
	//
	// However, the tokens will not be stored anywhere and are expected to be
	// invalid since not assigned by the server.
	ClientTokenLength int

	// QUICFrames specifies a list of QUIC frames to be sent in the first Initial
	// packet.
	//
	// If nil, it will be treated as a list with only a single QUICFrameCrypto.
	FrameOrder QUICFrames
}

func (ps *InitialPacketSpec) UpdateConfig(conf *Config) {
	conf.TokenStore = ps.getTokenStore()
}

func (ps *InitialPacketSpec) getTokenStore() TokenStore {
	if ps.TokenStore != nil {
		return ps.TokenStore
	}

	if ps.ClientTokenLength > 0 {
		return &dummyTokenStore{
			tokenLength: ps.ClientTokenLength,
		}
	}

	return nil
}

type dummyTokenStore struct {
	tokenLength int
}

func (d *dummyTokenStore) Pop(key string) (token *ClientToken) {
	var data []byte = make([]byte, d.tokenLength)
	rand.Read(data)

	return &ClientToken{
		data: data,
	}
}

func (d *dummyTokenStore) Put(_ string, _ *ClientToken) {
	// Do nothing
}

type QUICFrames []QUICFrame

func (qfs QUICFrames) MarshalWithCryptoData(cryptoData []byte) (payload []byte, err error) {
	if len(qfs) == 0 { // If no frames specified, send a single crypto frame
		qfs = QUICFrames{QUICFrameCrypto{0, 0}}
		return qfs.MarshalWithCryptoData(cryptoData)
	}

	for _, frame := range qfs {
		var frameBytes []byte
		if offset, length, cryptoOK := frame.CryptoFrameInfo(); cryptoOK {
			if length == 0 {
				// calculate length: from offset to the end of cryptoData
				length = len(cryptoData) - offset
			}
			frameBytes = []byte{0x06} // CRYPTO frame type
			frameBytes = quicvarint.Append(frameBytes, uint64(offset))
			frameBytes = quicvarint.Append(frameBytes, uint64(length))
			frameCryptoData := make([]byte, length)
			copy(frameCryptoData, cryptoData[offset:]) // copy at most length bytes
			frameBytes = append(frameBytes, frameCryptoData...)
		} else { // Handle none crypto frames: read and append to payload
			frameBytes, err = frame.Read()
			if err != nil {
				return nil, err
			}
		}
		payload = append(payload, frameBytes...)
	}
	return payload, nil
}

func (qfs QUICFrames) MarshalWithFrames(frames []byte) (payload []byte, err error) {
	// parse frames
	r := bytes.NewReader(frames)
	qchframes, err := clienthellod.ReadAllFrames(r)
	if err != nil {
		return nil, err
	}

	// parse crypto data
	cryptoData, err := clienthellod.ReassembleCRYPTOFrames(qchframes)
	if err != nil {
		return nil, err
	}

	// marshal
	return qfs.MarshalWithCryptoData(cryptoData)
}

type QUICFrame interface {
	// None crypto frames should return false for cryptoOK
	CryptoFrameInfo() (offset, length int, cryptoOK bool)

	// None crypto frames should return the byte representation of the frame.
	// Crypto frames' behavior is undefined and unused.
	Read() ([]byte, error)
}

// QUICFrameCrypto is used to specify the crypto frames containing the TLS ClientHello
// to be sent in the first Initial packet.
type QUICFrameCrypto struct {
	// Offset is used to specify the starting offset of the crypto frame.
	// Used when sending multiple crypto frames in a single packet.
	//
	// Multiple crypto frames in a single packet must not overlap and must
	// make up an entire crypto stream continuously.
	Offset int

	// Length is used to specify the length of the crypto frame.
	//
	// Must be set if it is NOT the last crypto frame in a packet.
	Length int
}

// CryptoFrameInfo() implements the QUICFrame interface.
//
// Crypto frames are later replaced by the crypto message using the information
// returned by this function.
func (q QUICFrameCrypto) CryptoFrameInfo() (offset, length int, cryptoOK bool) {
	return q.Offset, q.Length, true
}

// Read() implements the QUICFrame interface.
//
// Crypto frames are later replaced by the crypto message, so they are not Read()-able.
func (q QUICFrameCrypto) Read() ([]byte, error) {
	return nil, errors.New("crypto frames are not Read()-able")
}

// QUICFramePadding is used to specify the padding frames to be sent in the first Initial
// packet.
type QUICFramePadding struct {
	// Length is used to specify the length of the padding frame.
	Length int
}

// CryptoFrameInfo() implements the QUICFrame interface.
func (q QUICFramePadding) CryptoFrameInfo() (offset, length int, cryptoOK bool) {
	return 0, 0, false
}

// Read() implements the QUICFrame interface.
//
// Padding simply returns a slice of bytes of the specified length filled with 0.
func (q QUICFramePadding) Read() ([]byte, error) {
	return make([]byte, q.Length), nil
}

// QUICFramePing is used to specify the ping frames to be sent in the first Initial
// packet.
type QUICFramePing struct{}

// CryptoFrameInfo() implements the QUICFrame interface.
func (q QUICFramePing) CryptoFrameInfo() (offset, length int, cryptoOK bool) {
	return 0, 0, false
}

// Read() implements the QUICFrame interface.
//
// Ping simply returns a slice of bytes of size 1 with value 0x01(PING).
func (q QUICFramePing) Read() ([]byte, error) {
	return []byte{0x01}, nil
}
