// +build !gofuzz

package main

import (
	"bytes"
	"fmt"
	"math/rand"
	"os"
	"time"

	"github.com/lucas-clemente/quic-go"
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/qerr"
	"github.com/lucas-clemente/quic-go/internal/wire"
)

const version = protocol.VersionTLS

func getRandomData(l int) []byte {
	b := make([]byte, l)
	rand.Read(b)
	return b
}

func getRandomNumber() uint64 {
	switch 1 << uint8(rand.Intn(3)) {
	case 1:
		return uint64(rand.Int63n(64))
	case 2:
		return uint64(rand.Int63n(16384))
	case 4:
		return uint64(rand.Int63n(1073741824))
	case 8:
		return uint64(rand.Int63n(4611686018427387904))
	default:
		panic("unexpected length")
	}
}

func getRandomNumberLowerOrEqual(target uint64) uint64 {
	if target == 0 {
		return 0
	}
	return uint64(rand.Int63n(int64(target)))
}

// returns a *maximum* number of num ACK ranges
func getAckRanges(num int) []wire.AckRange {
	var ranges []wire.AckRange

	prevSmallest := uint64(rand.Int63n(4611686018427387904))
	for i := 0; i < num; i++ {
		if prevSmallest <= 2 {
			break
		}
		largest := getRandomNumberLowerOrEqual(prevSmallest - 2)
		smallest := getRandomNumberLowerOrEqual(largest)

		ranges = append(ranges, wire.AckRange{
			Smallest: protocol.PacketNumber(smallest),
			Largest:  protocol.PacketNumber(largest),
		})
		prevSmallest = smallest
	}
	return ranges
}

func getFrames() []wire.Frame {
	frames := []wire.Frame{
		&wire.StreamFrame{ // STREAM frame at 0 offset, with FIN bit
			StreamID: protocol.StreamID(getRandomNumber()),
			FinBit:   true,
		},
		&wire.StreamFrame{ // STREAM frame at 0 offset, with data and FIN bit
			StreamID: protocol.StreamID(getRandomNumber()),
			FinBit:   true,
			Data:     getRandomData(100),
		},
		&wire.StreamFrame{ // STREAM frame at non-zero offset, with data
			StreamID: protocol.StreamID(getRandomNumber()),
			Offset:   protocol.ByteCount(getRandomNumber()),
			Data:     getRandomData(50),
		},
		&wire.StreamFrame{ // STREAM frame at non-zero offset, with data and FIN bit
			StreamID: protocol.StreamID(getRandomNumber()),
			Offset:   protocol.ByteCount(getRandomNumber()),
			Data:     getRandomData(50),
			FinBit:   true,
		},
		&wire.StreamFrame{ // STREAM frame at non-zero offset, with data and FIN bit. Long enough to use the buffer.
			StreamID: protocol.StreamID(getRandomNumber()),
			Offset:   protocol.ByteCount(getRandomNumber()),
			Data:     getRandomData(2 * protocol.MinStreamFrameBufferSize),
			FinBit:   true,
		},
		&wire.StreamFrame{ // STREAM frame at maximum offset, with FIN bit
			StreamID: protocol.StreamID(getRandomNumber()),
			Offset:   protocol.MaxByteCount - 5,
			Data:     getRandomData(5),
			FinBit:   true,
		},
		&wire.StreamFrame{ // STREAM frame with data at maximum offset
			StreamID: protocol.StreamID(getRandomNumber()),
			Offset:   protocol.MaxByteCount,
			Data:     getRandomData(10),
		},
		&wire.AckFrame{
			AckRanges: getAckRanges(1),
			DelayTime: time.Duration(getRandomNumber()),
		},
		&wire.AckFrame{
			AckRanges: getAckRanges(5),
			DelayTime: time.Duration(getRandomNumber()),
		},
		&wire.AckFrame{
			AckRanges: getAckRanges(300),
			DelayTime: time.Duration(getRandomNumber()),
		},
		&wire.PingFrame{},
		&wire.ResetStreamFrame{
			StreamID:   protocol.StreamID(getRandomNumber()),
			ErrorCode:  quic.ErrorCode(getRandomNumber()),
			ByteOffset: protocol.ByteCount(getRandomNumber()),
		},
		&wire.ResetStreamFrame{ // at maximum offset
			StreamID:   protocol.StreamID(getRandomNumber()),
			ErrorCode:  quic.ErrorCode(getRandomNumber()),
			ByteOffset: protocol.MaxByteCount,
		},
		&wire.StopSendingFrame{
			StreamID:  protocol.StreamID(getRandomNumber()),
			ErrorCode: quic.ErrorCode(getRandomNumber()),
		},
		&wire.CryptoFrame{
			Data: getRandomData(100),
		},
		&wire.CryptoFrame{
			Offset: protocol.ByteCount(getRandomNumber()),
			Data:   getRandomData(50),
		},
		&wire.NewTokenFrame{
			Token: getRandomData(10),
		},
		&wire.MaxDataFrame{
			ByteOffset: protocol.ByteCount(getRandomNumber()),
		},
		&wire.MaxDataFrame{
			ByteOffset: protocol.MaxByteCount,
		},
		&wire.MaxStreamDataFrame{
			StreamID:   protocol.StreamID(getRandomNumber()),
			ByteOffset: protocol.ByteCount(getRandomNumber()),
		},
		&wire.MaxStreamDataFrame{
			StreamID:   protocol.StreamID(getRandomNumber()),
			ByteOffset: protocol.MaxByteCount,
		},
		&wire.MaxStreamsFrame{
			Type:         protocol.StreamTypeUni,
			MaxStreamNum: protocol.StreamNum(getRandomNumber()),
		},
		&wire.MaxStreamsFrame{
			Type:         protocol.StreamTypeBidi,
			MaxStreamNum: protocol.StreamNum(getRandomNumber()),
		},
		&wire.DataBlockedFrame{
			DataLimit: protocol.ByteCount(getRandomNumber()),
		},
		&wire.DataBlockedFrame{
			DataLimit: protocol.MaxByteCount,
		},
		&wire.StreamDataBlockedFrame{
			StreamID:  protocol.StreamID(getRandomNumber()),
			DataLimit: protocol.ByteCount(getRandomNumber()),
		},
		&wire.StreamDataBlockedFrame{
			StreamID:  protocol.StreamID(getRandomNumber()),
			DataLimit: protocol.MaxByteCount,
		},
		&wire.StreamsBlockedFrame{
			Type:        protocol.StreamTypeUni,
			StreamLimit: protocol.StreamNum(getRandomNumber()),
		},
		&wire.StreamsBlockedFrame{
			Type:        protocol.StreamTypeBidi,
			StreamLimit: protocol.StreamNum(getRandomNumber()),
		},
		&wire.RetireConnectionIDFrame{
			SequenceNumber: getRandomNumber(),
		},
		&wire.ConnectionCloseFrame{ // QUIC error with empty reason
			IsApplicationError: false,
			ErrorCode:          qerr.ErrorCode(getRandomNumber()),
			ReasonPhrase:       "",
		},
		&wire.ConnectionCloseFrame{ // QUIC error with reason
			IsApplicationError: false,
			// TODO: add frame type
			ErrorCode:    qerr.ErrorCode(getRandomNumber()),
			ReasonPhrase: string(getRandomData(100)),
		},
		&wire.ConnectionCloseFrame{ // application error with empty reason
			IsApplicationError: true,
			ErrorCode:          qerr.ErrorCode(getRandomNumber()),
			ReasonPhrase:       "",
		},
		&wire.ConnectionCloseFrame{ // application error with reason
			IsApplicationError: true,
			ErrorCode:          qerr.ErrorCode(getRandomNumber()),
			ReasonPhrase:       string(getRandomData(100)),
		},
	}

	seq1 := getRandomNumber()
	seq2 := getRandomNumber()
	var token1, token2 [16]byte
	copy(token1[:], getRandomData(16))
	copy(token2[:], getRandomData(16))
	frames = append(frames, []wire.Frame{
		&wire.NewConnectionIDFrame{
			SequenceNumber:      seq1,
			RetirePriorTo:       seq1 / 2,
			ConnectionID:        getRandomData(4),
			StatelessResetToken: token1,
		},
		&wire.NewConnectionIDFrame{
			SequenceNumber:      seq2,
			RetirePriorTo:       seq2,
			ConnectionID:        getRandomData(17),
			StatelessResetToken: token2,
		},
	}...)

	var data1 [8]byte
	copy(data1[:], getRandomData(8))
	frames = append(frames, &wire.PathChallengeFrame{
		Data: data1,
	})

	var data2 [8]byte
	copy(data2[:], getRandomData(8))
	frames = append(frames, &wire.PathResponseFrame{
		Data: data2,
	})

	return frames
}

func main() {
	rand.Seed(42)

	for i, f := range getFrames() {
		b := &bytes.Buffer{}
		if err := f.Write(b, version); err != nil {
			panic(err)
		}
		if err := writeCorpusFile(fmt.Sprintf("single-frame-%d", i), b.Bytes()); err != nil {
			panic(err)
		}
	}

	for i := 0; i < 25; i++ {
		frames := getFrames()

		b := &bytes.Buffer{}
		for j := 0; j < rand.Intn(30)+2; j++ {
			if rand.Intn(10) == 0 { // write a PADDING frame
				b.WriteByte(0x0)
			}
			f := frames[rand.Intn(len(frames))]
			if err := f.Write(b, version); err != nil {
				panic(err)
			}
			if rand.Intn(10) == 0 { // write a PADDING frame
				b.WriteByte(0x0)
			}
		}
		if err := writeCorpusFile(fmt.Sprintf("multiple-frames-%d", i), b.Bytes()); err != nil {
			panic(err)
		}
	}
}

func writeCorpusFile(name string, data []byte) error {
	file, err := os.Create("corpus/" + name)
	if err != nil {
		return err
	}
	data = append(getRandomData(1), data...)
	if _, err := file.Write(data); err != nil {
		return err
	}
	return file.Close()
}
