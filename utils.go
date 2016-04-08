package quic

import "io"

func readUintN(b io.ByteReader, length uint8) (uint64, error) {
	var res uint64
	for i := uint8(0); i < length; i++ {
		bt, err := b.ReadByte()
		if err != nil {
			return 0, err
		}
		res = res<<8 + uint64(bt)
	}
	return res, nil
}

func readUint32(b io.ByteReader) (uint32, error) {
	var b1, b2, b3, b4 uint8
	var err error
	if b1, err = b.ReadByte(); err != nil {
		return 0, err
	}
	if b2, err = b.ReadByte(); err != nil {
		return 0, err
	}
	if b3, err = b.ReadByte(); err != nil {
		return 0, err
	}
	if b4, err = b.ReadByte(); err != nil {
		return 0, err
	}
	return uint32(b1) + uint32(b2)<<8 + uint32(b3)<<16 + uint32(b4)<<24, nil
}

func readUint16(b io.ByteReader) (uint16, error) {
	var b1, b2 uint8
	var err error
	if b1, err = b.ReadByte(); err != nil {
		return 0, err
	}
	if b2, err = b.ReadByte(); err != nil {
		return 0, err
	}
	return uint16(b1) + uint16(b2)<<8, nil
}
