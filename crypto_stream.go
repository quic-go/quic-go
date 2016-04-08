package quic

import (
	"encoding/binary"
	"errors"
)

// A Tag in the QUIC crypto
type Tag uint32

const (
	// TagCHLO is a client hello
	TagCHLO Tag = 'C' + 'H'<<8 + 'L'<<16 + 'O'<<24

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
