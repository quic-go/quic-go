package h2quic

import (
	"net/http"

	"github.com/lucas-clemente/quic-go/protocol"
	"github.com/lucas-clemente/quic-go/utils"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

type mockQuicClient struct {
	streams map[protocol.StreamID]*mockStream
}

func (m *mockQuicClient) Close(error) error { panic("not implemented") }
func (m *mockQuicClient) Listen() error     { panic("not implemented") }
func (m *mockQuicClient) OpenStream(id protocol.StreamID) (utils.Stream, error) {
	_, ok := m.streams[id]
	if ok {
		panic("Stream already exists")
	}
	ms := &mockStream{id: id}
	m.streams[id] = ms
	return ms, nil
}

func newMockQuicClient() *mockQuicClient {
	return &mockQuicClient{
		streams: make(map[protocol.StreamID]*mockStream),
	}
}

var _ quicClient = &mockQuicClient{}

var _ = Describe("Client", func() {
	var client *Client
	var qClient *mockQuicClient

	BeforeEach(func() {
		var err error
		hostname := "quic.clemente.io:1337"
		client, err = NewClient(hostname)
		Expect(err).ToNot(HaveOccurred())
		Expect(client.hostname).To(Equal(hostname))
		qClient = newMockQuicClient()
		client.client = qClient
	})

	It("adds the port to the hostname, if none is given", func() {
		var err error
		client, err = NewClient("quic.clemente.io")
		Expect(err).ToNot(HaveOccurred())
		Expect(client.hostname).To(Equal("quic.clemente.io:443"))
	})

	It("opens the header stream only after the version has been negotiated", func() {
		Expect(client.headerStream).To(BeNil()) // header stream not yet opened
		err := client.versionNegotiateCallback()
		Expect(err).ToNot(HaveOccurred())
		Expect(client.headerStream).ToNot(BeNil())
		Expect(client.headerStream.StreamID()).To(Equal(protocol.StreamID(3)))
	})

	It("sets the correct crypto level", func() {
		Expect(client.encryptionLevel).To(Equal(protocol.Unencrypted))
		client.cryptoChangeCallback(false)
		Expect(client.encryptionLevel).To(Equal(protocol.EncryptionSecure))
		client.cryptoChangeCallback(true)
		Expect(client.encryptionLevel).To(Equal(protocol.EncryptionForwardSecure))
	})

	Context("Doing requests", func() {
		BeforeEach(func() {
			qClient.streams[3] = &mockStream{}
			client.requestWriter = newRequestWriter(qClient.streams[3])
		})

		It("does a request", func(done Done) {
			client.encryptionLevel = protocol.EncryptionForwardSecure
			req, err := http.NewRequest("https", "https://quic.clemente.io:1337/file1.dat", nil)
			Expect(err).ToNot(HaveOccurred())
			go client.Do(req)
			Eventually(func() []byte { return qClient.streams[3].dataWritten.Bytes() }).ShouldNot(BeEmpty())
			Expect(client.highestOpenedStream).Should(Equal(protocol.StreamID(5)))
			Expect(qClient.streams).Should(HaveKey(protocol.StreamID(5)))
			close(done)
		})

		Context("validating the address", func() {
			It("refuses to do requests for the wrong host", func() {
				req, err := http.NewRequest("https", "https://quic.clemente.io:1336/foobar.html", nil)
				Expect(err).ToNot(HaveOccurred())
				_, err = client.Do(req)
				Expect(err).To(MatchError("h2quic Client BUG: Do called for the wrong client"))
			})

			It("refuses to do plain HTTP requests", func() {
				req, err := http.NewRequest("https", "http://quic.clemente.io:1337/foobar.html", nil)
				Expect(err).ToNot(HaveOccurred())
				_, err = client.Do(req)
				Expect(err).To(MatchError("quic http2: unsupported scheme"))
			})

			It("adds the port for request URLs without one", func(done Done) {
				var err error
				client, err = NewClient("quic.clemente.io")
				Expect(err).ToNot(HaveOccurred())
				qClient.streams[3] = &mockStream{}
				client.requestWriter = newRequestWriter(qClient.streams[3])
				client.encryptionLevel = protocol.EncryptionForwardSecure
				req, err := http.NewRequest("https", "https://quic.clemente.io/foobar.html", nil)
				Expect(err).ToNot(HaveOccurred())
				_, err = client.Do(req)
				Expect(err).ToNot(HaveOccurred())
				close(done)
			})
		})
	})
})
