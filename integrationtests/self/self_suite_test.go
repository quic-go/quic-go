package self_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"log"
	"os"
	"runtime/pprof"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/integrationtests/tools"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/utils"
	"github.com/quic-go/quic-go/internal/wire"
	"github.com/quic-go/quic-go/logging"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
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

const logBufSize = 100 * 1 << 20 // initial size of the log buffer: 100 MB

type syncedBuffer struct {
	mutex sync.Mutex

	*bytes.Buffer
}

func (b *syncedBuffer) Write(p []byte) (int, error) {
	b.mutex.Lock()
	n, err := b.Buffer.Write(p)
	b.mutex.Unlock()
	return n, err
}

func (b *syncedBuffer) Bytes() []byte {
	b.mutex.Lock()
	p := b.Buffer.Bytes()
	b.mutex.Unlock()
	return p
}

func (b *syncedBuffer) Reset() {
	b.mutex.Lock()
	b.Buffer.Reset()
	b.mutex.Unlock()
}

var (
	logFileName  string // the log file set in the ginkgo flags
	logBufOnce   sync.Once
	logBuf       *syncedBuffer
	versionParam string

	qlogTracer func(context.Context, logging.Perspective, quic.ConnectionID) *logging.ConnectionTracer
	enableQlog bool

	version                          quic.VersionNumber
	tlsConfig                        *tls.Config
	tlsConfigLongChain               *tls.Config
	tlsClientConfig                  *tls.Config
	tlsClientConfigWithoutServerName *tls.Config
)

// read the logfile command line flag
// to set call ginkgo -- -logfile=log.txt
func init() {
	flag.StringVar(&logFileName, "logfile", "", "log file")
	flag.StringVar(&versionParam, "version", "1", "QUIC version")
	flag.BoolVar(&enableQlog, "qlog", false, "enable qlog")

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

var _ = BeforeSuite(func() {
	if enableQlog {
		qlogTracer = tools.NewQlogger(GinkgoWriter)
	}
	switch versionParam {
	case "1":
		version = quic.Version1
	case "2":
		version = quic.Version2
	default:
		Fail(fmt.Sprintf("unknown QUIC version: %s", versionParam))
	}
	fmt.Printf("Using QUIC version: %s\n", version)
	protocol.SupportedVersions = []quic.VersionNumber{version}
})

func getTLSConfig() *tls.Config {
	return tlsConfig.Clone()
}

func getTLSConfigWithLongCertChain() *tls.Config {
	return tlsConfigLongChain.Clone()
}

func getTLSClientConfig() *tls.Config {
	return tlsClientConfig.Clone()
}

func getTLSClientConfigWithoutServerName() *tls.Config {
	return tlsClientConfigWithoutServerName.Clone()
}

func getQuicConfig(conf *quic.Config) *quic.Config {
	if conf == nil {
		conf = &quic.Config{}
	} else {
		conf = conf.Clone()
	}
	if enableQlog {
		if conf.Tracer == nil {
			conf.Tracer = func(ctx context.Context, p logging.Perspective, connID quic.ConnectionID) *logging.ConnectionTracer {
				return logging.NewMultiplexedConnectionTracer(
					qlogTracer(ctx, p, connID),
					// multiplex it with an empty tracer to check that we're correctly ignoring unset callbacks everywhere
					&logging.ConnectionTracer{},
				)
			}
		} else if qlogTracer != nil {
			origTracer := conf.Tracer
			conf.Tracer = func(ctx context.Context, p logging.Perspective, connID quic.ConnectionID) *logging.ConnectionTracer {
				return logging.NewMultiplexedConnectionTracer(
					qlogTracer(ctx, p, connID),
					origTracer(ctx, p, connID),
				)
			}
		}
	}
	return conf
}

var _ = BeforeEach(func() {
	log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds)

	if debugLog() {
		logBufOnce.Do(func() {
			logBuf = &syncedBuffer{Buffer: bytes.NewBuffer(make([]byte, 0, logBufSize))}
		})
		utils.DefaultLogger.SetLogLevel(utils.LogLevelDebug)
		log.SetOutput(logBuf)
	}
})

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

var _ = AfterEach(func() {
	Expect(areHandshakesRunning()).To(BeFalse())
	Eventually(areTransportsRunning).Should(BeFalse())

	if debugLog() {
		logFile, err := os.Create(logFileName)
		Expect(err).ToNot(HaveOccurred())
		logFile.Write(logBuf.Bytes())
		logFile.Close()
		logBuf.Reset()
	}
})

// Debug says if this test is being logged
func debugLog() bool {
	return len(logFileName) > 0
}

func scaleDuration(d time.Duration) time.Duration {
	scaleFactor := 1
	if f, err := strconv.Atoi(os.Getenv("TIMESCALE_FACTOR")); err == nil { // parsing "" errors, so this works fine if the env is not set
		scaleFactor = f
	}
	Expect(scaleFactor).ToNot(BeZero())
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

func TestSelf(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Self integration tests")
}
