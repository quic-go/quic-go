package stresstest

import (
	"crypto/tls"
	"io"
	"math/rand"
	"sync"
	"sync/atomic"

	quic "github.com/lucas-clemente/quic-go"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = FDescribe("QUIC (without H2) tests", func() {
	var randSource io.Reader
	// var mutex sync.Mutex
	var totalDataLen uint64

	BeforeEach(func() {
		// utils.SetLogLevel(utils.LogLevelDebug)
		// f, err := os.Create("./log.txt")
		// if err != nil {
		// 	panic(err)
		// }
		// log.SetOutput(f)

		randSource = rand.New(rand.NewSource(GinkgoRandomSeed()))
	})

	getRandBuffer := func(dataLen int) []byte {
		data := make([]byte, dataLen)
		// mutex.Lock()
		// defer mutex.Unlock()
		// _, err := randSource.Read(data)
		// Expect(err).ToNot(HaveOccurred())
		return data
	}

	// write dataLen pseudorandom bytes on the stream and listens for the echo
	sendAndReceiveDataOnStream := func(str quic.Stream, dataLen int) {
		data := getRandBuffer(dataLen)
		go func() {
			defer GinkgoRecover()
			_, err := str.Write(data)
			Expect(err).ToNot(HaveOccurred())
			str.Close()
		}()
		dataEchoed := make([]byte, dataLen)
		n, err := io.ReadFull(str, dataEchoed)
		Expect(err).ToNot(HaveOccurred())
		Expect(n).To(Equal(dataLen))
		Expect(dataEchoed).To(Equal(data))
		atomic.AddUint64(&totalDataLen, uint64(n))
	}

	runTest := func(numClients, numStreams, dataLen int) {
		defer GinkgoRecover()

		var connWG sync.WaitGroup
		for i := 0; i < numClients; i++ {
			connWG.Add(1)
			go func(i int) {
				defer GinkgoRecover()
				conf := &quic.Config{TLSConfig: &tls.Config{InsecureSkipVerify: true}}
				client, err := quic.DialAddr("localhost:12345", conf)
				Expect(err).ToNot(HaveOccurred())

				var streamWG sync.WaitGroup
				for j := 0; j < numStreams; j++ {
					streamWG.Add(1)
					str, err := client.OpenStreamSync()
					Expect(err).ToNot(HaveOccurred())
					go func(str quic.Stream) {
						defer GinkgoRecover()
						sendAndReceiveDataOnStream(str, dataLen)
						streamWG.Done()
					}(str)
				}
				streamWG.Wait()
				client.Close(nil)
				connWG.Done()
			}(i)
		}
		connWG.Wait()
		Expect(totalDataLen).To(Equal(uint64(numClients) * uint64(numStreams) * uint64(dataLen)))
	}

	It("5 connections, 5 streams, 2048 bytes", func(done Done) {
		runTest(3, 80, 10*2048)
		close(done)
	}, 40)
})
