package self_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io"
	"math/rand"
	"net"
	"os"
	"runtime/pprof"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/integrationtests/tools"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/wire"
	"github.com/quic-go/quic-go/logging"

	"github.com/stretchr/testify/require"
)

const alpn = tools.ALPN

const (
	dataLen     = 500 * 1024       // 500 KB
	dataLenLong = 50 * 1024 * 1024 // 50 MB
)

var (
	// PRData contains dataLen bytes of pseudo-random data.
	PRData = GeneratePRData(dataLen)
	// PRDataLong contains dataLenLong bytes of pseudo-random data.
	PRDataLong = GeneratePRData(dataLenLong)
)

// See https://en.wikipedia.org/wiki/Lehmer_random_number_generator
func GeneratePRData(l int) []byte {
	res := make([]byte, l)
	seed := uint64(1)
	for i := 0; i < l; i++ {
		seed = seed * 48271 % 2147483647
		res[i] = byte(seed)
	}
	return res
}

var (
	version    quic.Version
	enableQlog bool

	tlsConfig                        *tls.Config
	tlsConfigLongChain               *tls.Config
	tlsClientConfig                  *tls.Config
	tlsClientConfigWithoutServerName *tls.Config
)

func init() {
	ca, caPrivateKey, err := tools.GenerateCA()
	if err != nil {
		panic(err)
	}
	leafCert, leafPrivateKey, err := tools.GenerateLeafCert(ca, caPrivateKey)
	if err != nil {
		panic(err)
	}
	tlsConfig = &tls.Config{
		Certificates: []tls.Certificate{{
			Certificate: [][]byte{leafCert.Raw},
			PrivateKey:  leafPrivateKey,
		}},
		NextProtos: []string{alpn},
	}
	tlsConfLongChain, err := tools.GenerateTLSConfigWithLongCertChain(ca, caPrivateKey)
	if err != nil {
		panic(err)
	}
	tlsConfigLongChain = tlsConfLongChain

	root := x509.NewCertPool()
	root.AddCert(ca)
	tlsClientConfig = &tls.Config{
		ServerName: "localhost",
		RootCAs:    root,
		NextProtos: []string{alpn},
	}
	tlsClientConfigWithoutServerName = &tls.Config{
		RootCAs:    root,
		NextProtos: []string{alpn},
	}
}

func getTLSConfig() *tls.Config                  { return tlsConfig.Clone() }
func getTLSConfigWithLongCertChain() *tls.Config { return tlsConfigLongChain.Clone() }
func getTLSClientConfig() *tls.Config            { return tlsClientConfig.Clone() }
func getTLSClientConfigWithoutServerName() *tls.Config {
	return tlsClientConfigWithoutServerName.Clone()
}

func getQuicConfig(conf *quic.Config) *quic.Config {
	if conf == nil {
		conf = &quic.Config{}
	} else {
		conf = conf.Clone()
	}
	if !enableQlog {
		return conf
	}
	if conf.Tracer == nil {
		conf.Tracer = func(ctx context.Context, p logging.Perspective, connID quic.ConnectionID) *logging.ConnectionTracer {
			return logging.NewMultiplexedConnectionTracer(
				tools.NewQlogConnectionTracer(os.Stdout)(ctx, p, connID),
				// multiplex it with an empty tracer to check that we're correctly ignoring unset callbacks everywhere
				&logging.ConnectionTracer{},
			)
		}
		return conf
	}
	origTracer := conf.Tracer
	conf.Tracer = func(ctx context.Context, p logging.Perspective, connID quic.ConnectionID) *logging.ConnectionTracer {
		tr := origTracer(ctx, p, connID)
		qlogger := tools.NewQlogConnectionTracer(os.Stdout)(ctx, p, connID)
		if tr == nil {
			return qlogger
		}
		return logging.NewMultiplexedConnectionTracer(qlogger, tr)
	}
	return conf
}

func addTracer(tr *quic.Transport) {
	if !enableQlog {
		return
	}
	if tr.Tracer == nil {
		tr.Tracer = logging.NewMultiplexedTracer(
			tools.QlogTracer(os.Stdout),
			// multiplex it with an empty tracer to check that we're correctly ignoring unset callbacks everywhere
			&logging.Tracer{},
		)
		return
	}
	origTracer := tr.Tracer
	tr.Tracer = logging.NewMultiplexedTracer(
		tools.QlogTracer(os.Stdout),
		origTracer,
	)
}

func newUDPConnLocalhost(t testing.TB) *net.UDPConn {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })
	return conn
}

func areHandshakesRunning() bool {
	var b bytes.Buffer
	pprof.Lookup("goroutine").WriteTo(&b, 1)
	return strings.Contains(b.String(), "RunHandshake")
}

func areTransportsRunning() bool {
	var b bytes.Buffer
	pprof.Lookup("goroutine").WriteTo(&b, 1)
	return strings.Contains(b.String(), "quic-go.(*Transport).listen")
}

func TestMain(m *testing.M) {
	var versionParam string
	flag.StringVar(&versionParam, "version", "1", "QUIC version")
	flag.BoolVar(&enableQlog, "qlog", false, "enable qlog")
	flag.Parse()

	switch versionParam {
	case "1":
		version = quic.Version1
	case "2":
		version = quic.Version2
	default:
		fmt.Printf("unknown QUIC version: %s\n", versionParam)
		os.Exit(1)
	}
	fmt.Printf("using QUIC version: %s\n", version)

	status := m.Run()
	if status != 0 {
		os.Exit(status)
	}
	if areHandshakesRunning() {
		fmt.Println("stray handshake goroutines found")
		os.Exit(1)
	}
	if areTransportsRunning() {
		fmt.Println("stray transport goroutines found")
		os.Exit(1)
	}
	os.Exit(status)
}

func scaleDuration(d time.Duration) time.Duration {
	scaleFactor := 1
	if f, err := strconv.Atoi(os.Getenv("TIMESCALE_FACTOR")); err == nil { // parsing "" errors, so this works fine if the env is not set
		scaleFactor = f
	}
	if scaleFactor == 0 {
		panic("TIMESCALE_FACTOR is 0")
	}
	return time.Duration(scaleFactor) * d
}

func newTracer(tracer *logging.ConnectionTracer) func(context.Context, logging.Perspective, quic.ConnectionID) *logging.ConnectionTracer {
	return func(context.Context, logging.Perspective, quic.ConnectionID) *logging.ConnectionTracer { return tracer }
}

type packet struct {
	time   time.Time
	hdr    *logging.ExtendedHeader
	frames []logging.Frame
}

type shortHeaderPacket struct {
	time   time.Time
	hdr    *logging.ShortHeader
	frames []logging.Frame
}

type packetCounter struct {
	closed                     chan struct{}
	sentShortHdr, rcvdShortHdr []shortHeaderPacket
	rcvdLongHdr                []packet
}

func (t *packetCounter) getSentShortHeaderPackets() []shortHeaderPacket {
	<-t.closed
	return t.sentShortHdr
}

func (t *packetCounter) getRcvdLongHeaderPackets() []packet {
	<-t.closed
	return t.rcvdLongHdr
}

func (t *packetCounter) getRcvd0RTTPacketNumbers() []protocol.PacketNumber {
	packets := t.getRcvdLongHeaderPackets()
	var zeroRTTPackets []protocol.PacketNumber
	for _, p := range packets {
		if p.hdr.Type == protocol.PacketType0RTT {
			zeroRTTPackets = append(zeroRTTPackets, p.hdr.PacketNumber)
		}
	}
	return zeroRTTPackets
}

func (t *packetCounter) getRcvdShortHeaderPackets() []shortHeaderPacket {
	<-t.closed
	return t.rcvdShortHdr
}

func newPacketTracer() (*packetCounter, *logging.ConnectionTracer) {
	c := &packetCounter{closed: make(chan struct{})}
	return c, &logging.ConnectionTracer{
		ReceivedLongHeaderPacket: func(hdr *logging.ExtendedHeader, _ logging.ByteCount, _ logging.ECN, frames []logging.Frame) {
			c.rcvdLongHdr = append(c.rcvdLongHdr, packet{time: time.Now(), hdr: hdr, frames: frames})
		},
		ReceivedShortHeaderPacket: func(hdr *logging.ShortHeader, _ logging.ByteCount, _ logging.ECN, frames []logging.Frame) {
			c.rcvdShortHdr = append(c.rcvdShortHdr, shortHeaderPacket{time: time.Now(), hdr: hdr, frames: frames})
		},
		SentShortHeaderPacket: func(hdr *logging.ShortHeader, _ logging.ByteCount, _ logging.ECN, ack *wire.AckFrame, frames []logging.Frame) {
			if ack != nil {
				frames = append(frames, ack)
			}
			c.sentShortHdr = append(c.sentShortHdr, shortHeaderPacket{time: time.Now(), hdr: hdr, frames: frames})
		},
		Close: func() { close(c.closed) },
	}
}

type readerWithTimeout struct {
	io.Reader
	Timeout time.Duration
}

func (r *readerWithTimeout) Read(p []byte) (n int, err error) {
	done := make(chan struct{})
	go func() {
		defer close(done)
		n, err = r.Reader.Read(p)
	}()

	select {
	case <-done:
		return n, err
	case <-time.After(r.Timeout):
		return 0, fmt.Errorf("read timeout after %s", r.Timeout)
	}
}

func randomDuration(min, max time.Duration) time.Duration {
	return min + time.Duration(rand.Int63n(int64(max-min)))
}

// contains0RTTPacket says if a packet contains a 0-RTT long header packet.
// It correctly handles coalesced packets.
func contains0RTTPacket(data []byte) bool {
	for len(data) > 0 {
		if !wire.IsLongHeaderPacket(data[0]) {
			return false
		}
		hdr, _, rest, err := wire.ParsePacket(data)
		if err != nil {
			return false
		}
		if hdr.Type == protocol.PacketType0RTT {
			return true
		}
		data = rest
	}
	return false
}
