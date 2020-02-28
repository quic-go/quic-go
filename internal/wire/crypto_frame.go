package wire

import (
	"bytes"
	"io"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
)

// A CryptoFrame is a CRYPTO frame
type CryptoFrame struct {
	Offset protocol.ByteCount
	Data   []byte
}

func parseCryptoFrame(r *bytes.Reader, _ protocol.VersionNumber) (*CryptoFrame, error) {
	if _, err := r.ReadByte(); err != nil {
		return nil, err
	}

	frame := &CryptoFrame{}
	offset, err := utils.ReadVarInt(r)
	if err != nil {
		return nil, err
	}
	frame.Offset = protocol.ByteCount(offset)
	dataLen, err := utils.ReadVarInt(r)
	if err != nil {
		return nil, err
	}
	if dataLen > uint64(r.Len()) {
		return nil, io.EOF
	}
	if dataLen != 0 {
		frame.Data = make([]byte, dataLen)
		if _, err := io.ReadFull(r, frame.Data); err != nil {
			// this should never happen, since we already checked the dataLen earlier
			return nil, err
		}
	}
	return frame, nil
}

func (f *CryptoFrame) Write(b *bytes.Buffer, _ protocol.VersionNumber) error {
	b.WriteByte(0x6)
	utils.WriteVarInt(b, uint64(f.Offset))
	utils.WriteVarInt(b, uint64(len(f.Data)))
	b.Write(f.Data)
	return nil
}

// Length of a written frame
func (f *CryptoFrame) Length(_ protocol.VersionNumber) protocol.ByteCount {
	return 1 + utils.VarIntLen(uint64(f.Offset)) + utils.VarIntLen(uint64(len(f.Data))) + protocol.ByteCount(len(f.Data))
}

// MaxDataLen returns the maximum data length
func (f *CryptoFrame) MaxDataLen(maxSize protocol.ByteCount) protocol.ByteCount {
	// pretend that the data size will be 1 bytes
	// if it turns out that varint encoding the length will consume 2 bytes, we need to adjust the data length afterwards
	headerLen := 1 + utils.VarIntLen(uint64(f.Offset)) + 1
	if headerLen > maxSize {
		return 0
	}
	maxDataLen := maxSize - headerLen
	if utils.VarIntLen(uint64(maxDataLen)) != 1 {
		maxDataLen--
	}
	return maxDataLen
}

// MaybeSplitOffFrame splits a frame such that it is not bigger than n bytes.
// It returns if the frame was actually split.
// The frame might not be split if:
// * the size is large enough to fit the whole frame
// * the size is too small to fit even a 1-byte frame. In that case, the frame returned is nil.
func (f *CryptoFrame) MaybeSplitOffFrame(maxSize protocol.ByteCount, version protocol.VersionNumber) (*CryptoFrame, bool /* was splitting required */) {
	if f.Length(version) <= maxSize {
		return nil, false
	}

	n := f.MaxDataLen(maxSize)
	if n == 0 {
		return nil, true
	}

	newLen := protocol.ByteCount(len(f.Data)) - n

	new := &CryptoFrame{}
	new.Offset = f.Offset
	new.Data = make([]byte, newLen)

	// swap the data slices
	new.Data, f.Data = f.Data, new.Data

	copy(f.Data, new.Data[n:])
	new.Data = new.Data[:n]
	f.Offset += n

	return new, true
}
