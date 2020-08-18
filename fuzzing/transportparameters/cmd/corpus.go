package main

import (
	"fmt"
	"log"
	"math"
	"math/rand"
	"net"
	"os"
	"time"

	"github.com/lucas-clemente/quic-go/internal/protocol"

	"github.com/lucas-clemente/quic-go/internal/wire"
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
	rand.Seed(1337)
	for i := 0; i < 20; i++ {
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
			ActiveConnectionIDLimit:        getRandomValue(),
		}
		if rand.Int()%2 == 0 {
			tp.OriginalDestinationConnectionID = protocol.ConnectionID(getRandomData(rand.Intn(50)))
		}
		if rand.Int()%2 == 0 {
			tp.InitialSourceConnectionID = protocol.ConnectionID(getRandomData(rand.Intn(50)))
		}
		if rand.Int()%2 == 0 {
			connID := protocol.ConnectionID(getRandomData(rand.Intn(50)))
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
				ConnectionID:        protocol.ConnectionID(getRandomData(rand.Intn(25))),
				StatelessResetToken: token,
			}
		}
		pers := protocol.PerspectiveServer
		if rand.Int()%2 == 0 {
			pers = protocol.PerspectiveClient
		}
		if err := writeCorpusFile(fmt.Sprintf("tp%d", i), tp.Marshal(pers)); err != nil {
			log.Fatal(err)
		}
	}
}

func writeCorpusFile(name string, data []byte) error {
	file, err := os.Create("corpus/" + name)
	if err != nil {
		return err
	}
	data = append(getRandomData(2), data...)
	if _, err := file.Write(data); err != nil {
		return err
	}
	return file.Close()
}
