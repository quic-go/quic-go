package main

import (
	"log"
	"math"
	"net"
	"time"

	"golang.org/x/exp/rand"

	"github.com/quic-go/quic-go/fuzzing/internal/helper"
	"github.com/quic-go/quic-go/fuzzing/transportparameters"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/wire"
)

func getRandomData(l int) []byte {
	b := make([]byte, l)
	rand.Read(b)
	return b
}

func getRandomValue() uint64 {
	maxVals := []int64{math.MaxUint8 / 4, math.MaxUint16 / 4, math.MaxUint32 / 4, math.MaxUint64 / 4}
	return uint64(rand.Int63n(maxVals[int(rand.Int31n(4))]))
}

func main() {
	for i := 0; i < 30; i++ {
		tp := &wire.TransportParameters{
			InitialMaxStreamDataBidiLocal:  protocol.ByteCount(getRandomValue()),
			InitialMaxStreamDataBidiRemote: protocol.ByteCount(getRandomValue()),
			InitialMaxStreamDataUni:        protocol.ByteCount(getRandomValue()),
			InitialMaxData:                 protocol.ByteCount(getRandomValue()),
			MaxAckDelay:                    time.Duration(getRandomValue()),
			AckDelayExponent:               uint8(getRandomValue()),
			DisableActiveMigration:         getRandomValue()%2 == 0,
			MaxUDPPayloadSize:              protocol.ByteCount(getRandomValue()),
			MaxUniStreamNum:                protocol.StreamNum(getRandomValue()),
			MaxBidiStreamNum:               protocol.StreamNum(getRandomValue()),
			MaxIdleTimeout:                 time.Duration(getRandomValue()),
			ActiveConnectionIDLimit:        getRandomValue() + 2,
		}
		if rand.Int()%2 == 0 {
			tp.OriginalDestinationConnectionID = protocol.ParseConnectionID(getRandomData(rand.Intn(21)))
		}
		if rand.Int()%2 == 0 {
			tp.InitialSourceConnectionID = protocol.ParseConnectionID(getRandomData(rand.Intn(21)))
		}
		if rand.Int()%2 == 0 {
			connID := protocol.ParseConnectionID(getRandomData(rand.Intn(21)))
			tp.RetrySourceConnectionID = &connID
		}
		if rand.Int()%2 == 0 {
			var token protocol.StatelessResetToken
			rand.Read(token[:])
			tp.StatelessResetToken = &token
		}
		if rand.Int()%2 == 0 {
			var token protocol.StatelessResetToken
			rand.Read(token[:])
			tp.PreferredAddress = &wire.PreferredAddress{
				IPv4:                net.IPv4(uint8(rand.Int()), uint8(rand.Int()), uint8(rand.Int()), uint8(rand.Int())),
				IPv4Port:            uint16(rand.Int()),
				IPv6:                net.IP(getRandomData(16)),
				IPv6Port:            uint16(rand.Int()),
				ConnectionID:        protocol.ParseConnectionID(getRandomData(rand.Intn(21))),
				StatelessResetToken: token,
			}
		}

		var data []byte
		if rand.Int()%2 == 0 {
			pers := protocol.PerspectiveServer
			if rand.Int()%2 == 0 {
				pers = protocol.PerspectiveClient
			}
			data = tp.Marshal(pers)
		} else {
			data = tp.MarshalForSessionTicket(nil)
		}
		if err := helper.WriteCorpusFileWithPrefix("corpus", data, transportparameters.PrefixLen); err != nil {
			log.Fatal(err)
		}
	}
}
