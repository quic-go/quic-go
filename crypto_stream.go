package quic

import (
	"errors"
	"fmt"
	"io"

	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/qerr"
	"github.com/quic-go/quic-go/internal/wire"
)

type baseCryptoStream struct {
	queue frameSorter

	highestOffset protocol.ByteCount
	finished      bool

	writeOffset protocol.ByteCount
	writeBuf    []byte
}

func newCryptoStream() *cryptoStream {
	return &cryptoStream{baseCryptoStream{queue: *newFrameSorter()}}
}

func (s *baseCryptoStream) HandleCryptoFrame(f *wire.CryptoFrame) error {
	highestOffset := f.Offset + protocol.ByteCount(len(f.Data))
	if maxOffset := highestOffset; maxOffset > protocol.MaxCryptoStreamOffset {
		return &qerr.TransportError{
			ErrorCode:    qerr.CryptoBufferExceeded,
			ErrorMessage: fmt.Sprintf("received invalid offset %d on crypto stream, maximum allowed %d", maxOffset, protocol.MaxCryptoStreamOffset),
		}
	}
	if s.finished {
		if highestOffset > s.highestOffset {
			// reject crypto data received after this stream was already finished
			return &qerr.TransportError{
				ErrorCode:    qerr.ProtocolViolation,
				ErrorMessage: "received crypto data after change of encryption level",
			}
		}
		// ignore data with a smaller offset than the highest received
		// could e.g. be a retransmission
		return nil
	}
	s.highestOffset = max(s.highestOffset, highestOffset)
	return s.queue.Push(f.Data, f.Offset, nil)
}

// GetCryptoData retrieves data that was received in CRYPTO frames
func (s *baseCryptoStream) GetCryptoData() []byte {
	_, data, _ := s.queue.Pop()
	return data
}

func (s *baseCryptoStream) Finish() error {
	if s.queue.HasMoreData() {
		return &qerr.TransportError{
			ErrorCode:    qerr.ProtocolViolation,
			ErrorMessage: "encryption level changed, but crypto stream has more data to read",
		}
	}
	s.finished = true
	return nil
}

// Writes writes data that should be sent out in CRYPTO frames
func (s *baseCryptoStream) Write(p []byte) (int, error) {
	s.writeBuf = append(s.writeBuf, p...)
	return len(p), nil
}

func (s *baseCryptoStream) HasData() bool {
	return len(s.writeBuf) > 0
}

func (s *baseCryptoStream) PopCryptoFrame(maxLen protocol.ByteCount) *wire.CryptoFrame {
	f := &wire.CryptoFrame{Offset: s.writeOffset}
	n := min(f.MaxDataLen(maxLen), protocol.ByteCount(len(s.writeBuf)))
	if n == 0 {
		return nil
	}
	f.Data = s.writeBuf[:n]
	s.writeBuf = s.writeBuf[n:]
	s.writeOffset += n
	return f
}

type cryptoStream struct {
	baseCryptoStream
}

type initialCryptoStream struct {
	baseCryptoStream

	scramble             bool
	sentPart1, sentPart2 bool
	cut1, cut2, end      protocol.ByteCount
}

func newInitialCryptoStream(isClient bool) *initialCryptoStream {
	return &initialCryptoStream{
		baseCryptoStream: baseCryptoStream{queue: *newFrameSorter()},
		scramble:         isClient,
		cut1:             protocol.InvalidByteCount,
		cut2:             protocol.InvalidByteCount,
	}
}

func (s *initialCryptoStream) HasData() bool {
	// The ClientHello might be written in multiple parts.
	// In order to correctly split the ClientHello, we need the entire ClientHello has been queued.
	if s.scramble && s.writeOffset == 0 &&
		s.cut1 == protocol.InvalidByteCount && s.cut2 == protocol.InvalidByteCount {
		return false
	}
	return s.baseCryptoStream.HasData()
}

func (s *initialCryptoStream) Write(p []byte) (int, error) {
	s.writeBuf = append(s.writeBuf, p...)
	if s.scramble && s.cut1 == protocol.InvalidByteCount && s.cut2 == protocol.InvalidByteCount {
		sniPos, sniLen, echPos, err := findSNIAndECH(s.writeBuf)
		if errors.Is(err, io.ErrUnexpectedEOF) {
			return len(p), nil
		}
		if err != nil {
			return len(p), err
		}
		if sniPos == -1 && echPos == -1 {
			// Neither SNI nor ECH found.
			// There's nothing to scramble.
			s.scramble = false
			return len(p), nil
		}
		sniCut := protocol.ByteCount(sniPos + sniLen/2) // right in the middle
		if echPos <= 0 {
			// no ECH extension found, just cut somewhere closely after the SNI start
			s.cut1 = sniCut
			s.cut2 = sniCut + min(20, protocol.ByteCount(len(s.writeBuf))-sniCut)
		} else {
			// ECH extension found, cut the ECH extension type value (a uint16) in half
			echCut := protocol.ByteCount(echPos + 1)
			s.cut1 = min(sniCut, echCut)
			s.cut2 = max(sniCut, echCut)
		}
		s.end = protocol.ByteCount(len(s.writeBuf))
	}
	return len(p), nil
}

func (s *initialCryptoStream) PopCryptoFrame(maxLen protocol.ByteCount) *wire.CryptoFrame {
	if !s.scramble {
		return s.baseCryptoStream.PopCryptoFrame(maxLen)
	}

	// part 1 first
	if s.writeOffset < s.cut1 {
		f := &wire.CryptoFrame{Offset: s.writeOffset}
		n := min(f.MaxDataLen(maxLen), s.cut1-s.writeOffset)
		if n == 0 {
			return nil
		}
		f.Data = s.writeBuf[:n]
		s.writeBuf = s.writeBuf[n:]
		s.writeOffset += n
		// once the first part is sent, switch to the third part
		if s.writeOffset >= s.cut1 {
			s.writeOffset = s.cut2
		}
		return f
	}

	// then part 3
	// absolute offset of the last byte written so far
	if s.writeOffset >= s.cut2 && s.writeOffset < s.end {
		f := &wire.CryptoFrame{Offset: s.writeOffset}
		n := min(f.MaxDataLen(maxLen), s.end-s.writeOffset)
		if n == 0 {
			return nil
		}
		start := s.writeOffset - s.cut1
		f.Data = s.writeBuf[start : start+n]
		// don't reslice the writeBuf, part 2 is not sent yet
		s.writeOffset += n
		// once the third part is sent, switch to the second part
		if s.writeOffset >= s.end {
			s.writeOffset = s.cut1
		}
		return f
	}

	// and part 2 last
	f := &wire.CryptoFrame{Offset: s.writeOffset}
	n := min(f.MaxDataLen(maxLen), s.cut2-s.writeOffset)
	if n == 0 {
		return nil
	}
	f.Data = s.writeBuf[:n]
	s.writeBuf = s.writeBuf[n:]
	s.writeOffset += n
	// once the second part is sent we're done with sending split data
	if s.writeOffset >= s.cut2 {
		s.writeBuf = s.writeBuf[s.end-s.writeOffset:]
		s.writeOffset = s.end
		s.scramble = false
	}
	return f
}
