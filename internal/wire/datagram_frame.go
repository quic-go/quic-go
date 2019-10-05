package wire

import (
	"bytes"
	"io"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
)

// A DatagramFrame is a DATAGRAM frame
type DatagramFrame struct {
	DataLenPresent bool
	Data           []byte
}

func parseDatagramFrame(r *bytes.Reader, _ protocol.VersionNumber) (*DatagramFrame, error) {
	typeByte, err := r.ReadByte()
	if err != nil {
		return nil, err
	}

	f := &DatagramFrame{}
	f.DataLenPresent = typeByte&0x1 > 0

	var length uint64
	if f.DataLenPresent {
		var err error
		len, err := utils.ReadVarInt(r)
		if err != nil {
			return nil, err
		}
		if len > uint64(r.Len()) {
			return nil, io.EOF
		}
		length = len
	} else {
		length = uint64(r.Len())
	}
	f.Data = make([]byte, length)
	if _, err := io.ReadFull(r, f.Data); err != nil {
		return nil, err
	}
	return f, nil
}

func (f *DatagramFrame) Write(b *bytes.Buffer, _ protocol.VersionNumber) error {
	typeByte := uint8(0x30)
	if f.DataLenPresent {
		typeByte ^= 0x1
	}
	b.WriteByte(typeByte)
	if f.DataLenPresent {
		utils.WriteVarInt(b, uint64(len(f.Data)))
	}
	b.Write(f.Data)
	return nil
}

// Length of a written frame
func (f *DatagramFrame) Length(_ protocol.VersionNumber) protocol.ByteCount {
	length := 1 + protocol.ByteCount(len(f.Data))
	if f.DataLenPresent {
		length += utils.VarIntLen(uint64(len(f.Data)))
	}
	return length
}
