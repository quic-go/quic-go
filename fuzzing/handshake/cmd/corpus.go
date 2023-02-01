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
	OnError(error)
	DropKeys(protocol.EncryptionLevel)
}

type runner struct {
	client, server *handshake.CryptoSetup
}

var _ handshakeRunner = &runner{}

func newRunner(client, server *handshake.CryptoSetup) *runner {
	return &runner{client: client, server: server}
}

func (r *runner) OnReceivedParams(*wire.TransportParameters) {}
func (r *runner) OnHandshakeComplete()                       {}
func (r *runner) OnError(err error) {
	(*r.client).Close()
	(*r.server).Close()
	log.Fatal("runner error:", err)
}
func (r *runner) DropKeys(protocol.EncryptionLevel) {}

const alpn = "fuzz"

func main() {
	cChunkChan, cInitialStream, cHandshakeStream := initStreams()
	var client, server handshake.CryptoSetup
	runner := newRunner(&client, &server)
	client, _ = handshake.NewCryptoSetupClient(
		cInitialStream,
		cHandshakeStream,
		protocol.ConnectionID{},
		nil,
		nil,
		&wire.TransportParameters{ActiveConnectionIDLimit: 2},
		runner,
		&tls.Config{
			ServerName:         "localhost",
			NextProtos:         []string{alpn},
			RootCAs:            testdata.GetRootCA(),
			ClientSessionCache: tls.NewLRUClientSessionCache(1),
		},
		false,
		utils.NewRTTStats(),
		nil,
		utils.DefaultLogger.WithPrefix("client"),
		protocol.VersionTLS,
	)

	sChunkChan, sInitialStream, sHandshakeStream := initStreams()
	config := testdata.GetTLSConfig()
	config.NextProtos = []string{alpn}
	server = handshake.NewCryptoSetupServer(
		sInitialStream,
		sHandshakeStream,
		protocol.ConnectionID{},
		nil,
		nil,
		&wire.TransportParameters{ActiveConnectionIDLimit: 2},
		runner,
		config,
		nil,
		utils.NewRTTStats(),
		nil,
		utils.DefaultLogger.WithPrefix("server"),
		protocol.VersionTLS,
	)

	serverHandshakeCompleted := make(chan struct{})
	go func() {
		defer close(serverHandshakeCompleted)
		server.RunHandshake()
	}()

	clientHandshakeCompleted := make(chan struct{})
	go func() {
		defer close(clientHandshakeCompleted)
		client.RunHandshake()
	}()

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
			server.HandleMessage(c.data, c.encLevel)
		case c := <-sChunkChan:
			messages = append(messages, c.data)
			client.HandleMessage(c.data, c.encLevel)
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
