package quic

import "io"

func readUint64(b io.ByteReader, length uint8) (uint64, error) {
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
