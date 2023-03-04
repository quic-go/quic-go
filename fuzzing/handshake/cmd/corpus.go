package main

import (
	"crypto/tls"
	"log"

	fuzzhandshake "github.com/quic-go/quic-go/fuzzing/handshake"
	"github.com/quic-go/quic-go/fuzzing/internal/helper"
	"github.com/quic-go/quic-go/internal/handshake"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/testdata"
	"github.com/quic-go/quic-go/internal/utils"
	"github.com/quic-go/quic-go/internal/wire"
)

type chunk struct {
	data     []byte
	encLevel protocol.EncryptionLevel
}

type stream struct {
	chunkChan chan<- chunk
	encLevel  protocol.EncryptionLevel
}

func (s *stream) Write(b []byte) (int, error) {
	data := append([]byte{}, b...)
	select {
	case s.chunkChan <- chunk{data: data, encLevel: s.encLevel}:
	default:
		panic("chunkChan too small")
	}
	return len(b), nil
}

func initStreams() (chan chunk, *stream /* initial */, *stream /* handshake */) {
	chunkChan := make(chan chunk, 10)
	initialStream := &stream{chunkChan: chunkChan, encLevel: protocol.EncryptionInitial}
	handshakeStream := &stream{chunkChan: chunkChan, encLevel: protocol.EncryptionHandshake}
	return chunkChan, initialStream, handshakeStream
}

type handshakeRunner interface {
	OnReceivedParams(*wire.TransportParameters)
	OnHandshakeComplete()
	OnReceivedReadKeys()
	DropKeys(protocol.EncryptionLevel)
}

type runner struct {
	handshakeComplete chan<- struct{}
}

var _ handshakeRunner = &runner{}

func newRunner(handshakeComplete chan<- struct{}) *runner {
	return &runner{handshakeComplete: handshakeComplete}
}

func (r *runner) OnReceivedParams(*wire.TransportParameters) {}
func (r *runner) OnReceivedReadKeys()                        {}
func (r *runner) OnHandshakeComplete() {
	close(r.handshakeComplete)
}
func (r *runner) DropKeys(protocol.EncryptionLevel) {}

const alpn = "fuzz"

func main() {
	cChunkChan, cInitialStream, cHandshakeStream := initStreams()
	var client, server handshake.CryptoSetup
	clientHandshakeCompleted := make(chan struct{})
	client, _ = handshake.NewCryptoSetupClient(
		cInitialStream,
		cHandshakeStream,
		nil,
		protocol.ConnectionID{},
		&wire.TransportParameters{ActiveConnectionIDLimit: 2},
		newRunner(clientHandshakeCompleted),
		&tls.Config{
			MinVersion:         tls.VersionTLS13,
			ServerName:         "localhost",
			NextProtos:         []string{alpn},
			RootCAs:            testdata.GetRootCA(),
			ClientSessionCache: tls.NewLRUClientSessionCache(1),
		},
		false,
		utils.NewRTTStats(),
		nil,
		utils.DefaultLogger.WithPrefix("client"),
		protocol.Version1,
	)

	sChunkChan, sInitialStream, sHandshakeStream := initStreams()
	config := testdata.GetTLSConfig()
	config.NextProtos = []string{alpn}
	serverHandshakeCompleted := make(chan struct{})
	server = handshake.NewCryptoSetupServer(
		sInitialStream,
		sHandshakeStream,
		nil,
		protocol.ConnectionID{},
		&wire.TransportParameters{ActiveConnectionIDLimit: 2},
		newRunner(serverHandshakeCompleted),
		config,
		false,
		utils.NewRTTStats(),
		nil,
		utils.DefaultLogger.WithPrefix("server"),
		protocol.Version1,
	)

	if err := client.StartHandshake(); err != nil {
		log.Fatal(err)
	}

	if err := server.StartHandshake(); err != nil {
		log.Fatal(err)
	}

	done := make(chan struct{})
	go func() {
		<-serverHandshakeCompleted
		<-clientHandshakeCompleted
		close(done)
	}()

	var messages [][]byte
messageLoop:
	for {
		select {
		case c := <-cChunkChan:
			messages = append(messages, c.data)
			if err := server.HandleMessage(c.data, c.encLevel); err != nil {
				log.Fatal(err)
			}
		case c := <-sChunkChan:
			messages = append(messages, c.data)
			if err := client.HandleMessage(c.data, c.encLevel); err != nil {
				log.Fatal(err)
			}
		case <-done:
			break messageLoop
		}
	}

	ticket, err := server.GetSessionTicket()
	if err != nil {
		log.Fatal(err)
	}
	if ticket == nil {
		log.Fatal("expected a session ticket")
	}
	messages = append(messages, ticket)

	for _, m := range messages {
		if err := helper.WriteCorpusFileWithPrefix("corpus", m, fuzzhandshake.PrefixLen); err != nil {
			log.Fatal(err)
		}
	}
}
