package handshake

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log"
	"math"
	mrand "math/rand/v2"
	"net"
	"time"

	"github.com/quic-go/quic-go/fuzzing/internal/helper"
	"github.com/quic-go/quic-go/internal/handshake"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/qtls"
	"github.com/quic-go/quic-go/internal/utils"
	"github.com/quic-go/quic-go/internal/wire"
)

var (
	cert, clientCert         *tls.Certificate
	certPool, clientCertPool *x509.CertPool
	sessionTicketKey         = [32]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32}
)

func init() {
	priv, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		log.Fatal(err)
	}
	cert, certPool, err = helper.GenerateCertificate(priv)
	if err != nil {
		log.Fatal(err)
	}

	privClient, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		log.Fatal(err)
	}
	clientCert, clientCertPool, err = helper.GenerateCertificate(privClient)
	if err != nil {
		log.Fatal(err)
	}
}

type messageType uint8

// TLS handshake message types.
const (
	typeClientHello         messageType = 1
	typeServerHello         messageType = 2
	typeNewSessionTicket    messageType = 4
	typeEncryptedExtensions messageType = 8
	typeCertificate         messageType = 11
	typeCertificateRequest  messageType = 13
	typeCertificateVerify   messageType = 15
	typeFinished            messageType = 20
)

func (m messageType) String() string {
	switch m {
	case typeClientHello:
		return "ClientHello"
	case typeServerHello:
		return "ServerHello"
	case typeNewSessionTicket:
		return "NewSessionTicket"
	case typeEncryptedExtensions:
		return "EncryptedExtensions"
	case typeCertificate:
		return "Certificate"
	case typeCertificateRequest:
		return "CertificateRequest"
	case typeCertificateVerify:
		return "CertificateVerify"
	case typeFinished:
		return "Finished"
	default:
		return fmt.Sprintf("unknown message type: %d", m)
	}
}

// consumes 3 bits
func getClientAuth(rand uint8) tls.ClientAuthType {
	switch rand {
	default:
		return tls.NoClientCert
	case 0:
		return tls.RequestClientCert
	case 1:
		return tls.RequireAnyClientCert
	case 2:
		return tls.VerifyClientCertIfGiven
	case 3:
		return tls.RequireAndVerifyClientCert
	}
}

const (
	alpn      = "fuzzing"
	alpnWrong = "wrong"
)

func toEncryptionLevel(n uint8) protocol.EncryptionLevel {
	switch n % 3 {
	default:
		return protocol.EncryptionInitial
	case 1:
		return protocol.EncryptionHandshake
	case 2:
		return protocol.Encryption1RTT
	}
}

func getTransportParameters(seed uint8) *wire.TransportParameters {
	const maxVarInt = math.MaxUint64 / 4
	r := mrand.New(mrand.NewPCG(uint64(seed), uint64(seed)))
	return &wire.TransportParameters{
		ActiveConnectionIDLimit:        2,
		InitialMaxData:                 protocol.ByteCount(r.IntN(maxVarInt)),
		InitialMaxStreamDataBidiLocal:  protocol.ByteCount(r.IntN(maxVarInt)),
		InitialMaxStreamDataBidiRemote: protocol.ByteCount(r.IntN(maxVarInt)),
		InitialMaxStreamDataUni:        protocol.ByteCount(r.IntN(maxVarInt)),
	}
}

// PrefixLen is the number of bytes used for configuration
const (
	PrefixLen = 12
	confLen   = 5
)

// Fuzz fuzzes the TLS 1.3 handshake used by QUIC.
//
//go:generate go run ./cmd/corpus.go
func Fuzz(data []byte) int {
	if len(data) < PrefixLen {
		return -1
	}
	dataLen := len(data)
	var runConfig1, runConfig2 [confLen]byte
	copy(runConfig1[:], data)
	data = data[confLen:]
	messageConfig1 := data[0]
	data = data[1:]
	copy(runConfig2[:], data)
	data = data[confLen:]
	messageConfig2 := data[0]
	data = data[1:]
	if dataLen != len(data)+PrefixLen {
		panic("incorrect configuration")
	}

	clientConf := &tls.Config{
		MinVersion: tls.VersionTLS13,
		ServerName: "localhost",
		NextProtos: []string{alpn},
		RootCAs:    certPool,
	}
	useSessionTicketCache := helper.NthBit(runConfig1[0], 2)
	if useSessionTicketCache {
		clientConf.ClientSessionCache = tls.NewLRUClientSessionCache(5)
	}

	if val := runHandshake(runConfig1, messageConfig1, clientConf, data); val != 1 {
		return val
	}
	return runHandshake(runConfig2, messageConfig2, clientConf, data)
}

func runHandshake(runConfig [confLen]byte, messageConfig uint8, clientConf *tls.Config, data []byte) int {
	serverConf := &tls.Config{
		MinVersion:       tls.VersionTLS13,
		Certificates:     []tls.Certificate{*cert},
		NextProtos:       []string{alpn},
		SessionTicketKey: sessionTicketKey,
	}

	// This sets the cipher suite for both client and server.
	// The way crypto/tls is designed doesn't allow us to set different cipher suites for client and server.
	resetCipherSuite := func() {}
	switch (runConfig[0] >> 6) % 4 {
	case 0:
		resetCipherSuite = qtls.SetCipherSuite(tls.TLS_AES_128_GCM_SHA256)
	case 1:
		resetCipherSuite = qtls.SetCipherSuite(tls.TLS_AES_256_GCM_SHA384)
	case 3:
		resetCipherSuite = qtls.SetCipherSuite(tls.TLS_CHACHA20_POLY1305_SHA256)
	default:
	}
	defer resetCipherSuite()

	enable0RTTClient := helper.NthBit(runConfig[0], 0)
	enable0RTTServer := helper.NthBit(runConfig[0], 1)
	sendPostHandshakeMessageToClient := helper.NthBit(runConfig[0], 3)
	sendPostHandshakeMessageToServer := helper.NthBit(runConfig[0], 4)
	sendSessionTicket := helper.NthBit(runConfig[0], 5)
	serverConf.ClientAuth = getClientAuth(runConfig[1] & 0b00000111)
	serverConf.SessionTicketsDisabled = helper.NthBit(runConfig[1], 3)
	if helper.NthBit(runConfig[2], 0) {
		clientConf.RootCAs = x509.NewCertPool()
	}
	if helper.NthBit(runConfig[2], 1) {
		serverConf.ClientCAs = clientCertPool
	} else {
		serverConf.ClientCAs = x509.NewCertPool()
	}
	if helper.NthBit(runConfig[2], 2) {
		serverConf.GetConfigForClient = func(*tls.ClientHelloInfo) (*tls.Config, error) {
			if helper.NthBit(runConfig[2], 3) {
				return nil, errors.New("getting client config failed")
			}
			if helper.NthBit(runConfig[2], 4) {
				return nil, nil
			}
			return serverConf, nil
		}
	}
	if helper.NthBit(runConfig[2], 5) {
		serverConf.GetCertificate = func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			if helper.NthBit(runConfig[2], 6) {
				return nil, errors.New("getting certificate failed")
			}
			if helper.NthBit(runConfig[2], 7) {
				return nil, nil
			}
			return clientCert, nil // this certificate will be invalid
		}
	}
	if helper.NthBit(runConfig[3], 0) {
		serverConf.VerifyPeerCertificate = func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			if helper.NthBit(runConfig[3], 1) {
				return errors.New("certificate verification failed")
			}
			return nil
		}
	}
	if helper.NthBit(runConfig[3], 2) {
		clientConf.VerifyPeerCertificate = func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			if helper.NthBit(runConfig[3], 3) {
				return errors.New("certificate verification failed")
			}
			return nil
		}
	}
	if helper.NthBit(runConfig[3], 4) {
		serverConf.NextProtos = []string{alpnWrong}
	}
	if helper.NthBit(runConfig[3], 5) {
		serverConf.NextProtos = []string{alpnWrong, alpn}
	}
	if helper.NthBit(runConfig[3], 6) {
		serverConf.KeyLogWriter = io.Discard
	}
	if helper.NthBit(runConfig[3], 7) {
		clientConf.KeyLogWriter = io.Discard
	}
	clientTP := getTransportParameters(runConfig[4] & 0x3)
	if helper.NthBit(runConfig[4], 3) {
		clientTP.MaxAckDelay = protocol.MaxMaxAckDelay + 5
	}
	serverTP := getTransportParameters(runConfig[4] & 0b00011000)
	if helper.NthBit(runConfig[4], 3) {
		serverTP.MaxAckDelay = protocol.MaxMaxAckDelay + 5
	}

	messageToReplace := messageConfig % 32
	messageToReplaceEncLevel := toEncryptionLevel(messageConfig >> 6)

	if len(data) == 0 {
		return -1
	}

	client := handshake.NewCryptoSetupClient(
		protocol.ConnectionID{},
		clientTP,
		clientConf,
		enable0RTTClient,
		&utils.RTTStats{},
		nil,
		utils.DefaultLogger.WithPrefix("client"),
		protocol.Version1,
	)
	if err := client.StartHandshake(context.Background()); err != nil {
		log.Fatal(err)
	}
	defer client.Close()

	server := handshake.NewCryptoSetupServer(
		protocol.ConnectionID{},
		&net.UDPAddr{IP: net.IPv6loopback, Port: 1234},
		&net.UDPAddr{IP: net.IPv6loopback, Port: 4321},
		serverTP,
		serverConf,
		enable0RTTServer,
		&utils.RTTStats{},
		nil,
		utils.DefaultLogger.WithPrefix("server"),
		protocol.Version1,
	)
	if err := server.StartHandshake(context.Background()); err != nil {
		log.Fatal(err)
	}
	defer server.Close()

	var clientHandshakeComplete, serverHandshakeComplete bool
	for {
		var processedEvent bool
	clientLoop:
		for {
			ev := client.NextEvent()
			//nolint:exhaustive // only need to process a few events
			switch ev.Kind {
			case handshake.EventNoEvent:
				if !processedEvent && !clientHandshakeComplete { // handshake stuck
					return 1
				}
				break clientLoop
			case handshake.EventWriteInitialData, handshake.EventWriteHandshakeData:
				msg := ev.Data
				encLevel := protocol.EncryptionInitial
				if ev.Kind == handshake.EventWriteHandshakeData {
					encLevel = protocol.EncryptionHandshake
				}
				if msg[0] == messageToReplace {
					fmt.Printf("replacing %s message to the server with %s at %s\n", messageType(msg[0]), messageType(data[0]), messageToReplaceEncLevel)
					msg = data
					encLevel = messageToReplaceEncLevel
				}
				if err := server.HandleMessage(msg, encLevel); err != nil {
					return 1
				}
			case handshake.EventHandshakeComplete:
				clientHandshakeComplete = true
			}
			processedEvent = true
		}

		processedEvent = false
	serverLoop:
		for {
			ev := server.NextEvent()
			//nolint:exhaustive // only need to process a few events
			switch ev.Kind {
			case handshake.EventNoEvent:
				if !processedEvent && !serverHandshakeComplete { // handshake stuck
					return 1
				}
				break serverLoop
			case handshake.EventWriteInitialData, handshake.EventWriteHandshakeData:
				encLevel := protocol.EncryptionInitial
				if ev.Kind == handshake.EventWriteHandshakeData {
					encLevel = protocol.EncryptionHandshake
				}
				msg := ev.Data
				if msg[0] == messageToReplace {
					fmt.Printf("replacing %s message to the client with %s at %s\n", messageType(msg[0]), messageType(data[0]), messageToReplaceEncLevel)
					msg = data
					encLevel = messageToReplaceEncLevel
				}
				if err := client.HandleMessage(msg, encLevel); err != nil {
					return 1
				}
			case handshake.EventHandshakeComplete:
				serverHandshakeComplete = true
			}
			processedEvent = true
		}

		if serverHandshakeComplete && clientHandshakeComplete {
			break
		}
	}

	_ = client.ConnectionState()
	_ = server.ConnectionState()

	sealer, err := client.Get1RTTSealer()
	if err != nil {
		panic("expected to get a 1-RTT sealer")
	}
	opener, err := server.Get1RTTOpener()
	if err != nil {
		panic("expected to get a 1-RTT opener")
	}
	const msg = "Lorem ipsum dolor sit amet, consectetur adipiscing elit."
	encrypted := sealer.Seal(nil, []byte(msg), 1337, []byte("foobar"))
	decrypted, err := opener.Open(nil, encrypted, time.Time{}, 1337, protocol.KeyPhaseZero, []byte("foobar"))
	if err != nil {
		panic(fmt.Sprintf("Decrypting message failed: %s", err.Error()))
	}
	if string(decrypted) != msg {
		panic("wrong message")
	}

	if sendSessionTicket && !serverConf.SessionTicketsDisabled {
		ticket, err := server.GetSessionTicket()
		if err != nil {
			panic(err)
		}
		if ticket == nil {
			panic("empty ticket")
		}
		client.HandleMessage(ticket, protocol.Encryption1RTT)
	}

	if sendPostHandshakeMessageToClient {
		fmt.Println("sending post handshake message to the client at", messageToReplaceEncLevel)
		client.HandleMessage(data, messageToReplaceEncLevel)
	}
	if sendPostHandshakeMessageToServer {
		fmt.Println("sending post handshake message to the server at", messageToReplaceEncLevel)
		server.HandleMessage(data, messageToReplaceEncLevel)
	}

	return 1
}
