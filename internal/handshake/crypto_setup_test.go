package handshake

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/qerr"
	"github.com/quic-go/quic-go/internal/testdata"
	"github.com/quic-go/quic-go/internal/utils"
	"github.com/quic-go/quic-go/internal/wire"

	"github.com/stretchr/testify/require"
)

const (
	typeClientHello      = 1
	typeNewSessionTicket = 4
)

type mockClientSessionCache struct {
	cache tls.ClientSessionCache
	puts  chan *tls.ClientSessionState
}

var _ tls.ClientSessionCache = &mockClientSessionCache{}

func newMockClientSessionCache() *mockClientSessionCache {
	return &mockClientSessionCache{
		puts:  make(chan *tls.ClientSessionState, 1),
		cache: tls.NewLRUClientSessionCache(1),
	}
}

func (m *mockClientSessionCache) Get(sessionKey string) (session *tls.ClientSessionState, ok bool) {
	return m.cache.Get(sessionKey)
}

func (m *mockClientSessionCache) Put(sessionKey string, cs *tls.ClientSessionState) {
	m.puts <- cs
	m.cache.Put(sessionKey, cs)
}

func getTLSConfigs() (clientConf, serverConf *tls.Config) {
	clientConf = &tls.Config{
		ServerName: "localhost",
		RootCAs:    testdata.GetRootCA(),
		NextProtos: []string{"crypto-setup"},
	}
	serverConf = testdata.GetTLSConfig()
	serverConf.NextProtos = []string{"crypto-setup"}
	return clientConf, serverConf
}

func TestErrorBeforeClientHelloGeneration(t *testing.T) {
	tlsConf := testdata.GetTLSConfig()
	tlsConf.InsecureSkipVerify = true
	tlsConf.NextProtos = []string{""}
	cl := NewCryptoSetupClient(
		protocol.ConnectionID{},
		&wire.TransportParameters{},
		tlsConf,
		false,
		&utils.RTTStats{},
		nil,
		utils.DefaultLogger.WithPrefix("client"),
		protocol.Version1,
	)

	var terr *qerr.TransportError
	err := cl.StartHandshake(context.Background())
	require.True(t, errors.As(err, &terr))
	require.Equal(t, uint64(0x100+0x50), uint64(terr.ErrorCode))
	require.Contains(t, err.Error(), "tls: invalid NextProtos value")
}

func TestMessageReceivedAtWrongEncryptionLevel(t *testing.T) {
	var token protocol.StatelessResetToken
	server := NewCryptoSetupServer(
		protocol.ConnectionID{},
		&net.UDPAddr{IP: net.IPv6loopback, Port: 1234},
		&net.UDPAddr{IP: net.IPv6loopback, Port: 4321},
		&wire.TransportParameters{StatelessResetToken: &token},
		testdata.GetTLSConfig(),
		false,
		&utils.RTTStats{},
		nil,
		utils.DefaultLogger.WithPrefix("server"),
		protocol.Version1,
	)

	require.NoError(t, server.StartHandshake(context.Background()))

	fakeCH := append([]byte{typeClientHello, 0, 0, 6}, []byte("foobar")...)
	// wrong encryption level
	err := server.HandleMessage(fakeCH, protocol.EncryptionHandshake)
	require.Error(t, err)
	require.Contains(t, err.Error(), "tls: handshake data received at wrong level")
}

func newRTTStatsWithRTT(t *testing.T, rtt time.Duration) *utils.RTTStats {
	t.Helper()
	rttStats := &utils.RTTStats{}
	rttStats.UpdateRTT(rtt, 0)
	require.Equal(t, rtt, rttStats.SmoothedRTT())
	return rttStats
}

// The clientEvents and serverEvents contain all events that were not processed by the function,
// i.e. not EventWriteInitialData, EventWriteHandshakeData, EventHandshakeComplete.
func handshake(t *testing.T, client, server CryptoSetup) (clientEvents []Event, clientErr error, serverEvents []Event, serverErr error) {
	t.Helper()
	require.NoError(t, client.StartHandshake(context.Background()))
	require.NoError(t, server.StartHandshake(context.Background()))

	var clientHandshakeComplete, serverHandshakeComplete bool

	for {
	clientLoop:
		for {
			ev := client.NextEvent()
			switch ev.Kind {
			case EventNoEvent:
				break clientLoop
			case EventWriteInitialData:
				serverErr = server.HandleMessage(ev.Data, protocol.EncryptionInitial)
				if serverErr != nil {
					return
				}
			case EventWriteHandshakeData:
				serverErr = server.HandleMessage(ev.Data, protocol.EncryptionHandshake)
				if serverErr != nil {
					return
				}
			case EventHandshakeComplete:
				clientHandshakeComplete = true
			default:
				clientEvents = append(clientEvents, ev)
			}
		}

	serverLoop:
		for {
			ev := server.NextEvent()
			switch ev.Kind {
			case EventNoEvent:
				break serverLoop
			case EventWriteInitialData:
				clientErr = client.HandleMessage(ev.Data, protocol.EncryptionInitial)
				if clientErr != nil {
					return
				}
			case EventWriteHandshakeData:
				clientErr = client.HandleMessage(ev.Data, protocol.EncryptionHandshake)
				if clientErr != nil {
					return
				}
			case EventHandshakeComplete:
				serverHandshakeComplete = true
				ticket, err := server.GetSessionTicket()
				require.NoError(t, err)
				if ticket != nil {
					require.NoError(t, client.HandleMessage(ticket, protocol.Encryption1RTT))
				}
			default:
				serverEvents = append(serverEvents, ev)
			}
		}

		if clientHandshakeComplete && serverHandshakeComplete {
			break
		}
	}
	return
}

func handshakeWithTLSConf(
	t *testing.T,
	clientConf, serverConf *tls.Config,
	clientRTTStats, serverRTTStats *utils.RTTStats,
	clientTransportParameters, serverTransportParameters *wire.TransportParameters,
	enable0RTT bool,
) (CryptoSetup /* client */, []Event /* more client events */, error, /* client error */
	CryptoSetup /* server */, []Event /* more server events */, error, /* server error */
) {
	t.Helper()
	client := NewCryptoSetupClient(
		protocol.ConnectionID{},
		clientTransportParameters,
		clientConf,
		enable0RTT,
		clientRTTStats,
		nil,
		utils.DefaultLogger.WithPrefix("client"),
		protocol.Version1,
	)

	if serverTransportParameters.StatelessResetToken == nil {
		var token protocol.StatelessResetToken
		serverTransportParameters.StatelessResetToken = &token
	}
	server := NewCryptoSetupServer(
		protocol.ConnectionID{},
		&net.UDPAddr{IP: net.IPv6loopback, Port: 1234},
		&net.UDPAddr{IP: net.IPv6loopback, Port: 4321},
		serverTransportParameters,
		serverConf,
		enable0RTT,
		serverRTTStats,
		nil,
		utils.DefaultLogger.WithPrefix("server"),
		protocol.Version1,
	)
	cEvents, cErr, sEvents, sErr := handshake(t, client, server)
	return client, cEvents, cErr, server, sEvents, sErr
}

func TestHandshake(t *testing.T) {
	clientConf, serverConf := getTLSConfigs()
	_, _, clientErr, _, _, serverErr := handshakeWithTLSConf(
		t,
		clientConf, serverConf,
		&utils.RTTStats{}, &utils.RTTStats{},
		&wire.TransportParameters{ActiveConnectionIDLimit: 2}, &wire.TransportParameters{ActiveConnectionIDLimit: 2},
		false,
	)
	require.NoError(t, clientErr)
	require.NoError(t, serverErr)
}

func TestHelloRetryRequest(t *testing.T) {
	clientConf, serverConf := getTLSConfigs()
	serverConf.CurvePreferences = []tls.CurveID{tls.CurveP384}
	_, _, clientErr, _, _, serverErr := handshakeWithTLSConf(
		t,
		clientConf, serverConf,
		&utils.RTTStats{}, &utils.RTTStats{},
		&wire.TransportParameters{ActiveConnectionIDLimit: 2}, &wire.TransportParameters{ActiveConnectionIDLimit: 2},
		false,
	)
	require.NoError(t, clientErr)
	require.NoError(t, serverErr)
}

func TestWithClientAuth(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{},
		SignatureAlgorithm:    x509.SHA256WithRSA,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		BasicConstraintsValid: true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, priv.Public(), priv)
	require.NoError(t, err)
	clientCert := tls.Certificate{
		PrivateKey:  priv,
		Certificate: [][]byte{certDER},
	}

	clientConf, serverConf := getTLSConfigs()
	clientConf.Certificates = []tls.Certificate{clientCert}
	serverConf.ClientAuth = tls.RequireAnyClientCert
	_, _, clientErr, _, _, serverErr := handshakeWithTLSConf(
		t,
		clientConf, serverConf,
		&utils.RTTStats{}, &utils.RTTStats{},
		&wire.TransportParameters{ActiveConnectionIDLimit: 2}, &wire.TransportParameters{ActiveConnectionIDLimit: 2},
		false,
	)
	require.NoError(t, clientErr)
	require.NoError(t, serverErr)
}

func TestTransportParameters(t *testing.T) {
	clientConf, serverConf := getTLSConfigs()
	cTransportParameters := &wire.TransportParameters{ActiveConnectionIDLimit: 2, MaxIdleTimeout: 42 * time.Second}
	client := NewCryptoSetupClient(
		protocol.ConnectionID{},
		cTransportParameters,
		clientConf,
		false,
		&utils.RTTStats{},
		nil,
		utils.DefaultLogger.WithPrefix("client"),
		protocol.Version1,
	)

	var token protocol.StatelessResetToken
	sTransportParameters := &wire.TransportParameters{
		MaxIdleTimeout:          1337 * time.Second,
		StatelessResetToken:     &token,
		ActiveConnectionIDLimit: 2,
	}
	server := NewCryptoSetupServer(
		protocol.ConnectionID{},
		&net.UDPAddr{IP: net.IPv6loopback, Port: 1234},
		&net.UDPAddr{IP: net.IPv6loopback, Port: 4321},
		sTransportParameters,
		serverConf,
		false,
		&utils.RTTStats{},
		nil,
		utils.DefaultLogger.WithPrefix("server"),
		protocol.Version1,
	)

	clientEvents, cErr, serverEvents, sErr := handshake(t, client, server)
	require.NoError(t, cErr)
	require.NoError(t, sErr)
	var clientReceivedTransportParameters *wire.TransportParameters
	for _, ev := range clientEvents {
		if ev.Kind == EventReceivedTransportParameters {
			clientReceivedTransportParameters = ev.TransportParameters
		}
	}
	require.NotNil(t, clientReceivedTransportParameters)
	require.Equal(t, 1337*time.Second, clientReceivedTransportParameters.MaxIdleTimeout)

	var serverReceivedTransportParameters *wire.TransportParameters
	for _, ev := range serverEvents {
		if ev.Kind == EventReceivedTransportParameters {
			serverReceivedTransportParameters = ev.TransportParameters
		}
	}
	require.NotNil(t, serverReceivedTransportParameters)
	require.Equal(t, 42*time.Second, serverReceivedTransportParameters.MaxIdleTimeout)
}

func TestNewSessionTicketAtWrongEncryptionLevel(t *testing.T) {
	clientConf, serverConf := getTLSConfigs()
	client, _, clientErr, _, _, serverErr := handshakeWithTLSConf(
		t,
		clientConf, serverConf,
		&utils.RTTStats{}, &utils.RTTStats{},
		&wire.TransportParameters{ActiveConnectionIDLimit: 2}, &wire.TransportParameters{ActiveConnectionIDLimit: 2},
		false,
	)
	require.NoError(t, clientErr)
	require.NoError(t, serverErr)

	// inject an invalid session ticket
	b := append([]byte{uint8(typeNewSessionTicket), 0, 0, 6}, []byte("foobar")...)
	err := client.HandleMessage(b, protocol.EncryptionHandshake)
	require.Error(t, err)
	require.Contains(t, err.Error(), "tls: handshake data received at wrong level")
}

func TestHandlingNewSessionTicketFails(t *testing.T) {
	clientConf, serverConf := getTLSConfigs()
	client, _, clientErr, _, _, serverErr := handshakeWithTLSConf(
		t,
		clientConf, serverConf,
		&utils.RTTStats{}, &utils.RTTStats{},
		&wire.TransportParameters{ActiveConnectionIDLimit: 2}, &wire.TransportParameters{ActiveConnectionIDLimit: 2},
		false,
	)
	require.NoError(t, clientErr)
	require.NoError(t, serverErr)

	// inject an invalid session ticket
	b := append([]byte{uint8(typeNewSessionTicket), 0, 0, 6}, []byte("foobar")...)
	err := client.HandleMessage(b, protocol.Encryption1RTT)
	require.IsType(t, &qerr.TransportError{}, err)
	require.True(t, err.(*qerr.TransportError).ErrorCode.IsCryptoError())
}

func TestSessionResumption(t *testing.T) {
	clientConf, serverConf := getTLSConfigs()
	csc := newMockClientSessionCache()
	clientConf.ClientSessionCache = csc
	const serverRTT = 25 * time.Millisecond // RTT as measured by the server. Should be restored.
	const clientRTT = 30 * time.Millisecond // RTT as measured by the client. Should be restored.
	serverOrigRTTStats := newRTTStatsWithRTT(t, serverRTT)
	clientOrigRTTStats := newRTTStatsWithRTT(t, clientRTT)
	client, _, clientErr, server, _, serverErr := handshakeWithTLSConf(
		t,
		clientConf, serverConf,
		clientOrigRTTStats, serverOrigRTTStats,
		&wire.TransportParameters{ActiveConnectionIDLimit: 2}, &wire.TransportParameters{ActiveConnectionIDLimit: 2},
		false,
	)
	require.NoError(t, clientErr)
	require.NoError(t, serverErr)
	select {
	case <-csc.puts:
	case <-time.After(time.Second):
		t.Fatal("didn't receive a session ticket")
	}
	require.False(t, server.ConnectionState().DidResume)
	require.False(t, client.ConnectionState().DidResume)

	clientRTTStats := &utils.RTTStats{}
	serverRTTStats := &utils.RTTStats{}
	client, _, clientErr, server, _, serverErr = handshakeWithTLSConf(
		t,
		clientConf, serverConf,
		clientRTTStats, serverRTTStats,
		&wire.TransportParameters{ActiveConnectionIDLimit: 2}, &wire.TransportParameters{ActiveConnectionIDLimit: 2},
		false,
	)
	require.NoError(t, clientErr)
	require.NoError(t, serverErr)
	select {
	case <-csc.puts:
	case <-time.After(time.Second):
		t.Fatal("didn't receive a session ticket")
	}
	require.True(t, server.ConnectionState().DidResume)
	require.True(t, client.ConnectionState().DidResume)
	require.Equal(t, clientRTT, clientRTTStats.SmoothedRTT())
	require.Equal(t, serverRTT, serverRTTStats.SmoothedRTT())
}

func TestSessionResumptionDisabled(t *testing.T) {
	clientConf, serverConf := getTLSConfigs()
	csc := newMockClientSessionCache()
	clientConf.ClientSessionCache = csc
	client, _, clientErr, server, _, serverErr := handshakeWithTLSConf(
		t,
		clientConf, serverConf,
		&utils.RTTStats{}, &utils.RTTStats{},
		&wire.TransportParameters{ActiveConnectionIDLimit: 2}, &wire.TransportParameters{ActiveConnectionIDLimit: 2},
		false,
	)
	require.NoError(t, clientErr)
	require.NoError(t, serverErr)
	select {
	case <-csc.puts:
	case <-time.After(time.Second):
		t.Fatal("didn't receive a session ticket")
	}
	require.False(t, server.ConnectionState().DidResume)
	require.False(t, client.ConnectionState().DidResume)

	serverConf.SessionTicketsDisabled = true
	client, _, clientErr, server, _, serverErr = handshakeWithTLSConf(
		t,
		clientConf, serverConf,
		&utils.RTTStats{}, &utils.RTTStats{},
		&wire.TransportParameters{ActiveConnectionIDLimit: 2}, &wire.TransportParameters{ActiveConnectionIDLimit: 2},
		false,
	)
	require.NoError(t, clientErr)
	require.NoError(t, serverErr)
	select {
	case <-csc.puts:
		t.Fatal("didn't expect to receive a session ticket")
	case <-time.After(25 * time.Millisecond):
	}
	require.False(t, server.ConnectionState().DidResume)
	require.False(t, client.ConnectionState().DidResume)
}

func Test0RTT(t *testing.T) {
	clientConf, serverConf := getTLSConfigs()
	csc := newMockClientSessionCache()
	clientConf.ClientSessionCache = csc
	const serverRTT = 25 * time.Millisecond // RTT as measured by the server. Should be restored.
	const clientRTT = 30 * time.Millisecond // RTT as measured by the client. Should be restored.
	serverOrigRTTStats := newRTTStatsWithRTT(t, serverRTT)
	clientOrigRTTStats := newRTTStatsWithRTT(t, clientRTT)
	const initialMaxData protocol.ByteCount = 1337
	client, _, clientErr, server, _, serverErr := handshakeWithTLSConf(
		t,
		clientConf, serverConf,
		clientOrigRTTStats, serverOrigRTTStats,
		&wire.TransportParameters{ActiveConnectionIDLimit: 2},
		&wire.TransportParameters{ActiveConnectionIDLimit: 2, InitialMaxData: initialMaxData},
		true,
	)
	require.NoError(t, clientErr)
	require.NoError(t, serverErr)
	select {
	case <-csc.puts:
	case <-time.After(time.Second):
		t.Fatal("didn't receive a session ticket")
	}
	require.False(t, server.ConnectionState().DidResume)
	require.False(t, client.ConnectionState().DidResume)

	clientRTTStats := &utils.RTTStats{}
	serverRTTStats := &utils.RTTStats{}
	client, clientEvents, clientErr, server, serverEvents, serverErr := handshakeWithTLSConf(
		t,
		clientConf, serverConf,
		clientRTTStats, serverRTTStats,
		&wire.TransportParameters{ActiveConnectionIDLimit: 2},
		&wire.TransportParameters{ActiveConnectionIDLimit: 2, InitialMaxData: initialMaxData},
		true,
	)
	require.NoError(t, clientErr)
	require.NoError(t, serverErr)
	require.Equal(t, clientRTT, clientRTTStats.SmoothedRTT())
	require.Equal(t, serverRTT, serverRTTStats.SmoothedRTT())

	var tp *wire.TransportParameters
	var clientReceived0RTTKeys bool
	for _, ev := range clientEvents {
		switch ev.Kind {
		case EventRestoredTransportParameters:
			tp = ev.TransportParameters
		case EventReceivedReadKeys:
			clientReceived0RTTKeys = true
		}
	}
	require.True(t, clientReceived0RTTKeys)
	require.NotNil(t, tp)
	require.Equal(t, initialMaxData, tp.InitialMaxData)

	var serverReceived0RTTKeys bool
	for _, ev := range serverEvents {
		switch ev.Kind {
		case EventReceivedReadKeys:
			serverReceived0RTTKeys = true
		}
	}
	require.True(t, serverReceived0RTTKeys)

	require.True(t, server.ConnectionState().DidResume)
	require.True(t, client.ConnectionState().DidResume)
	require.True(t, server.ConnectionState().Used0RTT)
	require.True(t, client.ConnectionState().Used0RTT)
}

func Test0RTTRejectionOnTransportParametersChanged(t *testing.T) {
	clientConf, serverConf := getTLSConfigs()
	csc := newMockClientSessionCache()
	clientConf.ClientSessionCache = csc
	const clientRTT = 30 * time.Millisecond // RTT as measured by the client. Should be restored.
	clientOrigRTTStats := newRTTStatsWithRTT(t, clientRTT)
	const initialMaxData protocol.ByteCount = 1337
	client, _, clientErr, server, _, serverErr := handshakeWithTLSConf(
		t,
		clientConf, serverConf,
		clientOrigRTTStats, &utils.RTTStats{},
		&wire.TransportParameters{ActiveConnectionIDLimit: 2},
		&wire.TransportParameters{ActiveConnectionIDLimit: 2, InitialMaxData: initialMaxData},
		true,
	)
	require.NoError(t, clientErr)
	require.NoError(t, serverErr)
	select {
	case <-csc.puts:
	case <-time.After(time.Second):
		t.Fatal("didn't receive a session ticket")
	}
	require.False(t, server.ConnectionState().DidResume)
	require.False(t, client.ConnectionState().DidResume)

	clientRTTStats := &utils.RTTStats{}
	client, clientEvents, clientErr, server, _, serverErr := handshakeWithTLSConf(
		t,
		clientConf, serverConf,
		clientRTTStats, &utils.RTTStats{},
		&wire.TransportParameters{ActiveConnectionIDLimit: 2},
		&wire.TransportParameters{ActiveConnectionIDLimit: 2, InitialMaxData: initialMaxData - 1},
		true,
	)
	require.NoError(t, clientErr)
	require.NoError(t, serverErr)
	require.Equal(t, clientRTT, clientRTTStats.SmoothedRTT())

	var tp *wire.TransportParameters
	var clientReceived0RTTKeys bool
	for _, ev := range clientEvents {
		switch ev.Kind {
		case EventRestoredTransportParameters:
			tp = ev.TransportParameters
		case EventReceivedReadKeys:
			clientReceived0RTTKeys = true
		}
	}
	require.True(t, clientReceived0RTTKeys)
	require.NotNil(t, tp)
	require.Equal(t, initialMaxData, tp.InitialMaxData)

	require.True(t, server.ConnectionState().DidResume)
	require.True(t, client.ConnectionState().DidResume)
	require.False(t, server.ConnectionState().Used0RTT)
	require.False(t, client.ConnectionState().Used0RTT)
}
