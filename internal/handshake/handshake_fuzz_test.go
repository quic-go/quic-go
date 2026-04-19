package handshake

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/qtls"
	"github.com/quic-go/quic-go/internal/utils"
	"github.com/quic-go/quic-go/internal/wire"
)

var (
	fuzzCert, fuzzAltCert *tls.Certificate
	fuzzCertPool          *x509.CertPool
)

func init() {
	var err error
	fuzzCert, fuzzCertPool, err = generateFuzzCertificate()
	if err != nil {
		panic(err)
	}
	fuzzAltCert, _, err = generateFuzzCertificate()
	if err != nil {
		panic(err)
	}
}

func generateFuzzCertificate() (*tls.Certificate, *x509.CertPool, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	tmpl := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{Organization: []string{"quic-go fuzzer"}},
		NotBefore:             time.Now().Add(-24 * time.Hour),
		NotAfter:              time.Now().Add(30 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:              []string{"localhost"},
		BasicConstraintsValid: true,
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, priv.Public(), priv)
	if err != nil {
		return nil, nil, err
	}
	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		return nil, nil, err
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return &tls.Certificate{
		Certificate: [][]byte{derBytes},
		PrivateKey:  priv,
	}, pool, nil
}

const fuzzALPN = "fuzzing"

var fuzzSessionTicketKey = [32]byte{
	1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
	17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32,
}

func FuzzHandshake(f *testing.F) {
	f.Add(
		uint8(0),    // cipherSuite
		uint8(0),    // clientAuth
		uint8(0xFF), // messageToReplace: won't match
		uint8(0),    // messageEncLevel
		uint8(0),    // zeroRTTMode
		uint8(0),    // postHandshakeTarget
		uint8(0),    // invalidTP
		uint8(0),    // sessionMode
		uint8(0),    // tlsCallbacks
		uint8(0),    // alpnMode
		[]byte("foobar"),
	)
	f.Add(
		uint8(2), // cipherSuite: ChaCha20
		uint8(0), // clientAuth
		uint8(1), // messageToReplace: ClientHello
		uint8(0), // messageEncLevel: Initial
		uint8(3), // zeroRTTMode: both
		uint8(0), // postHandshakeTarget
		uint8(0), // invalidTP
		uint8(1), // sessionMode: cache+ticket+enabled
		uint8(0), // tlsCallbacks
		uint8(0), // alpnMode
		[]byte("hello world"),
	)

	// Parameters:
	//   - cipherSuite (0-3): AES-128-GCM, AES-256-GCM, ChaCha20, default
	//   - clientAuth (0-4): maps to tls.ClientAuthType
	//   - messageToReplace: TLS message type byte to replace with fuzz data
	//   - messageEncLevel (0-2): encryption level for replaced message (Initial, Handshake, 1-RTT)
	//   - zeroRTTMode (0-3): 0=neither, 1=client, 2=server, 3=both
	//   - postHandshakeTarget (0-3): 0=neither, 1=client, 2=server, 3=both
	//   - invalidTP (0-3): 0=both valid, 1=client invalid, 2=server invalid, 3=both invalid
	//   - sessionMode (0-3): 0=no cache, 1=cache+ticket+enabled, 2=cache+disabled, 3=cache+no ticket
	//   - tlsCallbacks (0-15): getConfigForClient (val%4) x getCertificate (val/4)
	//     each: 0=off, 1=return value, 2=return error, 3=return nil
	//   - alpnMode (0-2): 0=correct, 1=wrong, 2=both correct and wrong
	f.Fuzz(func(t *testing.T, cipherSuite, clientAuth, messageToReplace, messageEncLevel, zeroRTTMode, postHandshakeTarget, invalidTP, sessionMode, tlsCallbacks, alpnMode uint8, data []byte) {
		if len(data) == 0 {
			return
		}
		if cipherSuite > 3 || clientAuth > 4 || messageEncLevel > 2 || zeroRTTMode > 3 || postHandshakeTarget > 3 || invalidTP > 3 || sessionMode > 3 || tlsCallbacks > 15 || alpnMode > 2 {
			return
		}

		clientConf := &tls.Config{
			MinVersion: tls.VersionTLS13,
			ServerName: "localhost",
			NextProtos: []string{fuzzALPN},
			RootCAs:    fuzzCertPool,
		}
		if sessionMode > 0 {
			clientConf.ClientSessionCache = tls.NewLRUClientSessionCache(5)
		}

		fuzzRunHandshake(t, cipherSuite, clientAuth, messageToReplace, messageEncLevel, zeroRTTMode, postHandshakeTarget, invalidTP, sessionMode, tlsCallbacks, alpnMode, clientConf, data)
		fuzzRunHandshake(t, cipherSuite, clientAuth, messageToReplace, messageEncLevel, zeroRTTMode, postHandshakeTarget, invalidTP, sessionMode, tlsCallbacks, alpnMode, clientConf, data)
	})
}

func fuzzRunHandshake(
	t *testing.T,
	cipherSuiteVal, clientAuthVal, messageToReplace, messageEncLevelVal, zeroRTTMode, postHandshakeTarget, invalidTP, sessionMode, tlsCallbacks, alpnMode uint8,
	clientConf *tls.Config,
	data []byte,
) {
	t.Helper()

	switch cipherSuiteVal {
	case 0:
		defer qtls.SetCipherSuite(tls.TLS_AES_128_GCM_SHA256)()
	case 1:
		defer qtls.SetCipherSuite(tls.TLS_AES_256_GCM_SHA384)()
	case 2:
		defer qtls.SetCipherSuite(tls.TLS_CHACHA20_POLY1305_SHA256)()
	case 3:
		// use default cipher suites
	}

	var tlsClientAuth tls.ClientAuthType
	switch clientAuthVal {
	case 0:
		tlsClientAuth = tls.NoClientCert
	case 1:
		tlsClientAuth = tls.RequestClientCert
	case 2:
		tlsClientAuth = tls.RequireAnyClientCert
	case 3:
		tlsClientAuth = tls.VerifyClientCertIfGiven
	case 4:
		tlsClientAuth = tls.RequireAndVerifyClientCert
	}

	var msgEncLevel protocol.EncryptionLevel
	switch messageEncLevelVal {
	case 0:
		msgEncLevel = protocol.EncryptionInitial
	case 1:
		msgEncLevel = protocol.EncryptionHandshake
	case 2:
		msgEncLevel = protocol.Encryption1RTT
	}

	serverConf := &tls.Config{
		MinVersion:       tls.VersionTLS13,
		Certificates:     []tls.Certificate{*fuzzCert},
		NextProtos:       []string{fuzzALPN},
		SessionTicketKey: fuzzSessionTicketKey,
		ClientAuth:       tlsClientAuth,
	}

	enable0RTTClient := zeroRTTMode == 1 || zeroRTTMode == 3
	enable0RTTServer := zeroRTTMode == 2 || zeroRTTMode == 3
	sendPostHandshakeToClient := postHandshakeTarget == 1 || postHandshakeTarget == 3
	sendPostHandshakeToServer := postHandshakeTarget == 2 || postHandshakeTarget == 3

	sendSessionTicket := sessionMode == 1
	serverConf.SessionTicketsDisabled = sessionMode == 2

	getConfigForClient := tlsCallbacks % 4
	getCertificate := tlsCallbacks / 4

	if getConfigForClient > 0 {
		serverConf.GetConfigForClient = func(*tls.ClientHelloInfo) (*tls.Config, error) {
			switch getConfigForClient {
			case 1:
				return serverConf, nil
			case 2:
				return nil, errors.New("getting client config failed")
			case 3:
				return nil, nil
			}
			return nil, nil
		}
	}
	if getCertificate > 0 {
		serverConf.GetCertificate = func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			switch getCertificate {
			case 1:
				return fuzzAltCert, nil
			case 2:
				return nil, errors.New("getting certificate failed")
			case 3:
				return nil, nil
			}
			return nil, nil
		}
	}

	switch alpnMode {
	case 1:
		serverConf.NextProtos = []string{"wrong"}
	case 2:
		serverConf.NextProtos = []string{"wrong", fuzzALPN}
	}

	clientTP := &wire.TransportParameters{
		ActiveConnectionIDLimit:        2,
		InitialMaxData:                 1 << 20,
		InitialMaxStreamDataBidiLocal:  1 << 16,
		InitialMaxStreamDataBidiRemote: 1 << 16,
		InitialMaxStreamDataUni:        1 << 16,
	}
	serverTP := &wire.TransportParameters{
		ActiveConnectionIDLimit:        2,
		InitialMaxData:                 1 << 20,
		InitialMaxStreamDataBidiLocal:  1 << 16,
		InitialMaxStreamDataBidiRemote: 1 << 16,
		InitialMaxStreamDataUni:        1 << 16,
	}
	if invalidTP == 1 || invalidTP == 3 {
		clientTP.MaxAckDelay = protocol.MaxMaxAckDelay + 5
	}
	if invalidTP == 2 || invalidTP == 3 {
		serverTP.MaxAckDelay = protocol.MaxMaxAckDelay + 5
	}

	client := NewCryptoSetupClient(
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
		t.Fatal(err)
	}
	defer client.Close()

	server := NewCryptoSetupServer(
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
		t.Fatal(err)
	}
	defer server.Close()

	var clientHandshakeComplete, serverHandshakeComplete bool
	for {
		var processedEvent bool
	clientLoop:
		for {
			ev := client.NextEvent()
			switch ev.Kind {
			case EventNoEvent:
				if !processedEvent && !clientHandshakeComplete {
					return
				}
				break clientLoop
			case EventWriteInitialData, EventWriteHandshakeData:
				msg := ev.Data
				encLevel := protocol.EncryptionInitial
				if ev.Kind == EventWriteHandshakeData {
					encLevel = protocol.EncryptionHandshake
				}
				if msg[0] == messageToReplace {
					msg = data
					encLevel = msgEncLevel
				}
				if err := server.HandleMessage(msg, encLevel); err != nil {
					return
				}
			case EventHandshakeComplete:
				clientHandshakeComplete = true
			}
			processedEvent = true
		}
		processedEvent = false
	serverLoop:
		for {
			ev := server.NextEvent()
			switch ev.Kind {
			case EventNoEvent:
				if !processedEvent && !serverHandshakeComplete {
					return
				}
				break serverLoop
			case EventWriteInitialData, EventWriteHandshakeData:
				msg := ev.Data
				encLevel := protocol.EncryptionInitial
				if ev.Kind == EventWriteHandshakeData {
					encLevel = protocol.EncryptionHandshake
				}
				if msg[0] == messageToReplace {
					msg = data
					encLevel = msgEncLevel
				}
				if err := client.HandleMessage(msg, encLevel); err != nil {
					return
				}
			case EventHandshakeComplete:
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
		t.Fatal("expected to get a 1-RTT sealer")
	}
	opener, err := server.Get1RTTOpener()
	if err != nil {
		t.Fatal("expected to get a 1-RTT opener")
	}
	const plaintext = "Lorem ipsum dolor sit amet, consectetur adipiscing elit."
	encrypted := sealer.Seal(nil, []byte(plaintext), 1337, []byte("foobar"))
	decrypted, err := opener.Open(nil, encrypted, 0, 1337, protocol.KeyPhaseZero, []byte("foobar"))
	if err != nil {
		t.Fatalf("decrypting message failed: %s", err)
	}
	if string(decrypted) != plaintext {
		t.Fatal("decrypted message doesn't match")
	}

	if sendSessionTicket && !serverConf.SessionTicketsDisabled {
		ticket, err := server.GetSessionTicket()
		if err != nil {
			t.Fatalf("error getting session ticket: %s", err)
		}
		if ticket == nil {
			t.Fatal("expected non-nil session ticket")
		}
		client.HandleMessage(ticket, protocol.Encryption1RTT)
	}

	if sendPostHandshakeToClient {
		client.HandleMessage(data, msgEncLevel)
	}
	if sendPostHandshakeToServer {
		server.HandleMessage(data, msgEncLevel)
	}
}
