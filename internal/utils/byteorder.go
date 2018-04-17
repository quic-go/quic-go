package utils

import (
	"io"
)

// A ByteOrder specifies how to convert byte sequences into 16-, 32-, or 64-bit unsigned integers.
type ByteOrder interface {
	ReadUintN(b io.ByteReader, length uint8) (uint64, error)
	ReadUint64(io.ByteReader) (uint64, error)
	ReadUint32(io.ByteReader) (uint32, error)
	ReadUint16(io.ByteReader) (uint16, error)

	WriteUint64(ByteWriter, uint64)
	WriteUint56(ByteWriter, uint64)
	WriteUint48(ByteWriter, uint64)
	WriteUint40(ByteWriter, uint64)
	WriteUint32(ByteWriter, uint32)
	WriteUint24(ByteWriter, uint32)
	WriteUint16(ByteWriter, uint16)

	ReadUfloat16(io.ByteReader) (uint64, error)
	WriteUfloat16(ByteWriter, uint64)
}
