package handshake

import (
	"bytes"
	"encoding/binary"
	"errors"
	"sort"

	"github.com/lucas-clemente/quic-go/utils"
)

var (
	errHandshakeMessageEOF = errors.New("ParseHandshakeMessage: Unexpected EOF")
)

// ParseHandshakeMessage reads a crypto message
func ParseHandshakeMessage(data []byte) (Tag, map[Tag][]byte, error) {
	if len(data) < 8 {
		return 0, nil, errHandshakeMessageEOF
	}

	messageTag := Tag(binary.LittleEndian.Uint32(data[0:4]))
	nPairs := int(binary.LittleEndian.Uint16(data[4:6]))

	data = data[8:]

	// We need space for at least nPairs * 8 bytes
	if len(data) < int(nPairs)*8 {
		return 0, nil, errHandshakeMessageEOF
	}

	resultMap := map[Tag][]byte{}

	dataStart := 0
	for indexPos := 0; indexPos < nPairs*8; indexPos += 8 {
		// We know from the check above that data is long enough for the index
		tag := Tag(binary.LittleEndian.Uint32(data[indexPos : indexPos+4]))
		dataEnd := int(binary.LittleEndian.Uint32(data[indexPos+4 : indexPos+8]))

		if dataEnd > len(data) {
			return 0, nil, errHandshakeMessageEOF
		}
		if dataEnd < dataStart {
			return 0, nil, errors.New("invalid end offset in crypto message")
		}

		resultMap[tag] = data[nPairs*8+dataStart : nPairs*8+dataEnd]
		dataStart = dataEnd
	}

	return messageTag, resultMap, nil
}

// WriteHandshakeMessage writes a crypto message
func WriteHandshakeMessage(b *bytes.Buffer, messageTag Tag, data map[Tag][]byte) {
	utils.WriteUint32(b, uint32(messageTag))
	utils.WriteUint16(b, uint16(len(data)))
	utils.WriteUint16(b, 0)

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
	sort.Sort(utils.Uint32Slice(tags))

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
