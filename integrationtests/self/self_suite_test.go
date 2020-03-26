package self_test

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"log"
	"math/rand"
	"os"
	"sync"
	"testing"

	"github.com/lucas-clemente/quic-go"

	"github.com/lucas-clemente/quic-go/internal/testdata"
	"github.com/lucas-clemente/quic-go/internal/utils"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

const alpn = "quic-go integration tests"

func getTLSConfig() *tls.Config {
	conf := testdata.GetTLSConfig()
	conf.NextProtos = []string{alpn}
	return conf
}

func getTLSClientConfig() *tls.Config {
	return &tls.Config{
		RootCAs:    testdata.GetRootCA(),
		NextProtos: []string{alpn},
	}
}

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
	logFileName string // the log file set in the ginkgo flags
	logBufOnce  sync.Once
	logBuf      *syncedBuffer
	enableQlog  bool
)

// read the logfile command line flag
// to set call ginkgo -- -logfile=log.txt
func init() {
	flag.StringVar(&logFileName, "logfile", "", "log file")
	flag.BoolVar(&enableQlog, "qlog", false, "enable qlog")
}

func getQuicConfigForClient(conf *quic.Config) *quic.Config {
	return getQuicConfigForRole("client", conf)
}

func getQuicConfigForServer(conf *quic.Config) *quic.Config {
	return getQuicConfigForRole("server", conf)
}

func getQuicConfigForRole(role string, conf *quic.Config) *quic.Config {
	if conf == nil {
		conf = &quic.Config{}
	} else {
		conf = conf.Clone()
	}
	if !enableQlog {
		return conf
	}
	conf.GetLogWriter = func(connectionID []byte) io.WriteCloser {
		filename := fmt.Sprintf("log_%x_%s.qlog", connectionID, role)
		fmt.Fprintf(GinkgoWriter, "Creating %s.\n", filename)
		f, err := os.Create(filename)
		Expect(err).ToNot(HaveOccurred())
		bw := bufio.NewWriter(f)
		return utils.NewBufferedWriteCloser(bw, f)
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

var _ = AfterEach(func() {
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

func TestSelf(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Self integration tests")
}

var _ = BeforeSuite(func() {
	rand.Seed(GinkgoRandomSeed())
})
