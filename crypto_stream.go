package quic

import (
	"bytes"
	"encoding/binary"
	"errors"
	"sort"
)

// A Tag in the QUIC crypto
type Tag uint32

const (
	// TagCHLO is a client hello
	TagCHLO Tag = 'C' + 'H'<<8 + 'L'<<16 + 'O'<<24
	// TagREJ is a server hello rejection
	TagREJ Tag = 'R' + 'E'<<8 + 'J'<<16
	// TagSCFG is a server config
	TagSCFG Tag = 'S' + 'C'<<8 + 'F'<<16 + 'G'<<24

	// TagPAD is padding
	TagPAD Tag = 'P' + 'A'<<8 + 'D'<<16
	// TagSNI is the server name indication
	TagSNI Tag = 'S' + 'N'<<8 + 'I'<<16
	// TagVER is the QUIC version
	TagVER Tag = 'V' + 'E'<<8 + 'R'<<16
	// TagCCS is the hash of the common certificate sets
	TagCCS Tag = 'C' + 'C'<<8 + 'S'<<16
	// TagMSPC is max streams per connection
	TagMSPC Tag = 'M' + 'S'<<8 + 'P'<<16 + 'C'<<24
	// TagUAID is the user agent ID
	TagUAID Tag = 'U' + 'A'<<8 + 'I'<<16 + 'D'<<24
	// TagTCID is truncation of the connection ID
	TagTCID Tag = 'T' + 'C'<<8 + 'I'<<16 + 'D'<<24
	// TagPDMD is the proof demand
	TagPDMD Tag = 'P' + 'D'<<8 + 'M'<<16 + 'D'<<24
	// TagSRBF is the socket receive buffer
	TagSRBF Tag = 'S' + 'R'<<8 + 'B'<<16 + 'F'<<24
	// TagICSL is the idle connection state lifetime
	TagICSL Tag = 'I' + 'C'<<8 + 'S'<<16 + 'L'<<24
	// TagNONP is the client proof nonce
	TagNONP Tag = 'N' + 'O'<<8 + 'N'<<16 + 'P'<<24
	// TagSCLS is the silently close timeout
	TagSCLS Tag = 'S' + 'C'<<8 + 'L'<<16 + 'S'<<24
	// TagCSCT is the signed cert timestamp (RFC6962) of leaf cert
	TagCSCT Tag = 'C' + 'S'<<8 + 'C'<<16 + 'T'<<24
	// TagCOPT are the connection options
	TagCOPT Tag = 'C' + 'O'<<8 + 'P'<<16 + 'T'<<24
	// TagCFCW is the initial session/connection flow control receive window
	TagCFCW Tag = 'C' + 'F'<<8 + 'C'<<16 + 'W'<<24
	// TagSFCW is the initial stream flow control receive window.
	TagSFCW Tag = 'S' + 'F'<<8 + 'C'<<16 + 'W'<<24

	// TagSTK is the source-address token
	TagSTK Tag = 'S' + 'T'<<8 + 'K'<<16
	// TagSNO is the server nonce
	TagSNO Tag = 'S' + 'N'<<8 + 'O'<<16
	// TagPROF is the server proof
	TagPROF Tag = 'P' + 'R'<<8 + 'O'<<16 + 'F'<<24

	// TagSCID is the server config ID
	TagSCID Tag = 'S' + 'C'<<8 + 'I'<<16 + 'D'<<24
	// TagKEXS is the list of key exchange algos
	TagKEXS Tag = 'K' + 'E'<<8 + 'X'<<16 + 'S'<<24
	// TagAEAD is the list of AEAD algos
	TagAEAD Tag = 'A' + 'E'<<8 + 'A'<<16 + 'D'<<24
	// TagPUBS is the public value for the KEX
	TagPUBS Tag = 'P' + 'U'<<8 + 'B'<<16 + 'S'<<24
	// TagORBT is the client orbit
	TagORBT Tag = 'O' + 'R'<<8 + 'B'<<16 + 'T'<<24
	// TagEXPY is the server config expiry
	TagEXPY Tag = 'E' + 'X'<<8 + 'P'<<16 + 'Y'<<24
)

var (
	errCryptoMessageEOF = errors.New("ParseCryptoMessage: Unexpected EOF")
)

// ParseCryptoMessage reads a crypto message
func ParseCryptoMessage(data []byte) (Tag, map[Tag][]byte, error) {
	if len(data) < 8 {
		return 0, nil, errCryptoMessageEOF
	}

	messageTag := Tag(binary.LittleEndian.Uint32(data[0:4]))
	nPairs := int(binary.LittleEndian.Uint16(data[4:6]))

	data = data[8:]

	// We need space for at least nPairs * 8 bytes
	if len(data) < int(nPairs)*8 {
		return 0, nil, errCryptoMessageEOF
	}

	resultMap := map[Tag][]byte{}

	dataStart := 0
	for indexPos := 0; indexPos < nPairs*8; indexPos += 8 {
		// We know from the check above that data is long enough for the index
		tag := Tag(binary.LittleEndian.Uint32(data[indexPos : indexPos+4]))
		dataEnd := int(binary.LittleEndian.Uint32(data[indexPos+4 : indexPos+8]))

		if dataEnd > len(data) {
			return 0, nil, errCryptoMessageEOF
		}
		if dataEnd < dataStart {
			return 0, nil, errors.New("invalid end offset in crypto message")
		}

		resultMap[tag] = data[nPairs*8+dataStart : nPairs*8+dataEnd]
		dataStart = dataEnd
	}

	return messageTag, resultMap, nil
}

// WriteCryptoMessage writes a crypto message
func WriteCryptoMessage(b *bytes.Buffer, messageTag Tag, data map[Tag][]byte) {
	writeUint32(b, uint32(messageTag))
	writeUint16(b, uint16(len(data)))
	writeUint16(b, 0)

	// Save current position in the buffer, so that we can update the index in-place later
	indexStart := b.Len()

	indexData := make([]byte, 8*len(data))
	b.Write(indexData) // Will be updated later

	// Sort the tags
	tags := make([]uint32, len(data))
	i := 0
	for t := range data {
		tags[i] = uint32(t)
		i++
	}
	sort.Sort(Uint32Slice(tags))

	offset := uint32(0)
	for i, t := range tags {
		v := data[Tag(t)]
		b.Write(v)
		offset += uint32(len(v))
		binary.LittleEndian.PutUint32(indexData[i*8:], t)
		binary.LittleEndian.PutUint32(indexData[i*8+4:], offset)
	}

	// Now we write the index data for real
	copy(b.Bytes()[indexStart:], indexData)
}
