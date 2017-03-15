package h2quic

import (
	"bytes"
	"compress/gzip"
	"crypto/tls"
	"errors"
	"net"
	"net/http"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"

	quic "github.com/lucas-clemente/quic-go"
	"github.com/lucas-clemente/quic-go/protocol"
	"github.com/lucas-clemente/quic-go/qerr"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Client", func() {
	var (
		client        *Client
		session       *mockSession
		headerStream  *mockStream
		quicTransport *QuicRoundTripper
	)

	BeforeEach(func() {
		quicTransport = &QuicRoundTripper{}
		hostname := "quic.clemente.io:1337"
		client = NewClient(quicTransport, nil, hostname)
		Expect(client.hostname).To(Equal(hostname))
		session = &mockSession{}
		client.session = session

		headerStream = &mockStream{id: 3}
		client.headerStream = headerStream
		client.requestWriter = newRequestWriter(headerStream)
	})

	It("saves the TLS config", func() {
		tlsConf := &tls.Config{InsecureSkipVerify: true}
		client = NewClient(&QuicRoundTripper{}, tlsConf, "")
		Expect(client.config.TLSConfig).To(Equal(tlsConf))
	})

	It("adds the port to the hostname, if none is given", func() {
		client = NewClient(quicTransport, nil, "quic.clemente.io")
		Expect(client.hostname).To(Equal("quic.clemente.io:443"))
	})

	It("dials", func() {
		udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
		Expect(err).ToNot(HaveOccurred())
		client = NewClient(quicTransport, nil, udpConn.LocalAddr().String())
		go client.Dial()
		data := make([]byte, 100)
		_, err = udpConn.Read(data)
		hdr, err := quic.ParsePublicHeader(bytes.NewReader(data), protocol.PerspectiveClient)
		Expect(err).ToNot(HaveOccurred())
		Expect(hdr.VersionFlag).To(BeTrue())
		Expect(hdr.ConnectionID).ToNot(BeNil())
	})

	It("saves the session when the ConnState callback is called", func() {
		client.session = nil // unset the session set in BeforeEach
		client.config.ConnState(session, quic.ConnStateForwardSecure)
		Expect(client.session).To(Equal(session))
	})

	It("opens the header stream only after the version has been negotiated", func() {
		client.headerStream = nil // unset the headerStream openend in the BeforeEach
		session.streamToOpen = headerStream
		Expect(client.headerStream).To(BeNil()) // header stream not yet opened
		// now start the actual test
		client.config.ConnState(session, quic.ConnStateVersionNegotiated)
		Expect(client.headerStream).ToNot(BeNil())
		Expect(client.headerStream.StreamID()).To(Equal(protocol.StreamID(3)))
	})

	It("errors if it can't open the header stream", func() {
		testErr := errors.New("test error")
		client.headerStream = nil // unset the headerStream openend in the BeforeEach
		session.streamOpenErr = testErr
		client.config.ConnState(session, quic.ConnStateVersionNegotiated)
		Expect(session.closed).To(BeTrue())
		Expect(session.closedWithError).To(MatchError(testErr))
	})

	It("errors if the header stream has the wrong StreamID", func() {
		session.streamToOpen = &mockStream{id: 1337}
		client.config.ConnState(session, quic.ConnStateVersionNegotiated)
		Expect(session.closed).To(BeTrue())
		Expect(session.closedWithError).To(MatchError("h2quic Client BUG: StreamID of Header Stream is not 3"))
	})

	It("sets the correct crypto level", func() {
		Expect(client.encryptionLevel).To(Equal(protocol.EncryptionUnencrypted))
		client.config.ConnState(session, quic.ConnStateSecure)
		Expect(client.encryptionLevel).To(Equal(protocol.EncryptionSecure))
		client.config.ConnState(session, quic.ConnStateForwardSecure)
		Expect(client.encryptionLevel).To(Equal(protocol.EncryptionForwardSecure))
	})

	Context("Doing requests", func() {
		var request *http.Request
		var dataStream *mockStream

		getRequest := func(data []byte) *http2.MetaHeadersFrame {
			r := bytes.NewReader(data)
			decoder := hpack.NewDecoder(4096, func(hf hpack.HeaderField) {})
			h2framer := http2.NewFramer(nil, r)
			frame, err := h2framer.ReadFrame()
			Expect(err).ToNot(HaveOccurred())
			mhframe := &http2.MetaHeadersFrame{HeadersFrame: frame.(*http2.HeadersFrame)}
			mhframe.Fields, err = decoder.DecodeFull(mhframe.HeadersFrame.HeaderBlockFragment())
			Expect(err).ToNot(HaveOccurred())
			return mhframe
		}

		getHeaderFields := func(f *http2.MetaHeadersFrame) map[string]string {
			fields := make(map[string]string)
			for _, hf := range f.Fields {
				fields[hf.Name] = hf.Value
			}
			return fields
		}

		BeforeEach(func() {
			var err error
			client.encryptionLevel = protocol.EncryptionForwardSecure
			request, err = http.NewRequest("https", "https://quic.clemente.io:1337/file1.dat", nil)
			Expect(err).ToNot(HaveOccurred())

			dataStream = &mockStream{id: 5}
			session.streamToOpen = dataStream
		})

		It("does a request", func(done Done) {
			var doRsp *http.Response
			var doErr error
			var doReturned bool
			go func() {
				doRsp, doErr = client.Do(request)
				doReturned = true
			}()

			Eventually(func() []byte { return headerStream.dataWritten.Bytes() }).ShouldNot(BeEmpty())
			Expect(client.responses).To(HaveKey(protocol.StreamID(5)))
			rsp := &http.Response{
				Status:     "418 I'm a teapot",
				StatusCode: 418,
			}
			client.responses[5] <- rsp
			Eventually(func() bool { return doReturned }).Should(BeTrue())
			Expect(doErr).ToNot(HaveOccurred())
			Expect(doRsp).To(Equal(rsp))
			Expect(doRsp.Body).To(Equal(dataStream))
			Expect(doRsp.ContentLength).To(BeEquivalentTo(-1))
			Expect(doRsp.Request).To(Equal(request))
			close(done)
		})

		It("closes the quic client when encountering an error on the header stream", func() {
			var doRsp *http.Response
			var doErr error
			var doReturned bool
			go func() {
				doRsp, doErr = client.Do(request)
				doReturned = true
			}()

			Eventually(func() chan *http.Response {
				client.mutex.RLock()
				defer client.mutex.RUnlock()
				return client.responses[5]
			}).ShouldNot(BeNil())

			headerStream.dataToRead.Write([]byte("invalid response"))
			client.handleHeaderStream()

			Eventually(func() bool { return doReturned }).Should(BeTrue())
			Expect(client.headerErr).To(MatchError(qerr.Error(qerr.HeadersStreamDataDecompressFailure, "cannot read frame")))
			Expect(doErr).To(MatchError(client.headerErr))
			Expect(doRsp).To(BeNil())
			Expect(client.session.(*mockSession).closedWithError).To(MatchError(client.headerErr))
		})

		It("blocks if no stream is available", func() {
			session.blockOpenStreamSync = true
			var doReturned bool
			go func() {
				defer GinkgoRecover()
				_, err := client.Do(request)
				Expect(err).ToNot(HaveOccurred())
				doReturned = true
			}()
			headerStream.dataToRead.Write([]byte("invalid response"))
			go client.handleHeaderStream()

			Consistently(func() bool { return doReturned }).Should(BeFalse())
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
				client = NewClient(quicTransport, nil, "quic.clemente.io")
				req, err := http.NewRequest("https", "https://quic.clemente.io/foobar.html", nil)
				Expect(err).ToNot(HaveOccurred())

				var doErr error
				var doReturned bool
				// the client.Do will block, because the encryption level is still set to Unencrypted
				go func() {
					_, doErr = client.Do(req)
					doReturned = true
				}()

				Consistently(doReturned).Should(BeFalse())
				Expect(doErr).ToNot(HaveOccurred())
				close(done)
			})
		})

		It("sets the EndStream header for requests without a body", func() {
			go func() { client.Do(request) }()
			Eventually(func() []byte { return headerStream.dataWritten.Bytes() }).ShouldNot(BeNil())
			mhf := getRequest(headerStream.dataWritten.Bytes())
			Expect(mhf.HeadersFrame.StreamEnded()).To(BeTrue())
		})

		It("sets the EndStream header to false for requests with a body", func() {
			request.Body = &mockBody{}
			go func() { client.Do(request) }()
			Eventually(func() []byte { return headerStream.dataWritten.Bytes() }).ShouldNot(BeNil())
			mhf := getRequest(headerStream.dataWritten.Bytes())
			Expect(mhf.HeadersFrame.StreamEnded()).To(BeFalse())
		})

		Context("requests containing a Body", func() {
			var requestBody []byte
			var response *http.Response

			BeforeEach(func() {
				requestBody = []byte("request body")
				body := &mockBody{}
				body.SetData(requestBody)
				request.Body = body
				response = &http.Response{
					StatusCode: 200,
					Header:     http.Header{"Content-Length": []string{"1000"}},
				}
			})

			It("sends a request", func() {
				var doRsp *http.Response
				var doErr error
				var doReturned bool
				go func() {
					doRsp, doErr = client.Do(request)
					doReturned = true
				}()
				Eventually(func() chan *http.Response { return client.responses[5] }).ShouldNot(BeNil())
				client.responses[5] <- response
				Eventually(func() bool { return doReturned }).Should(BeTrue())
				Expect(dataStream.dataWritten.Bytes()).To(Equal(requestBody))
				Expect(dataStream.closed).To(BeTrue())
				Expect(request.Body.(*mockBody).closed).To(BeTrue())
				Expect(doErr).ToNot(HaveOccurred())
				Expect(doRsp).To(Equal(response))
			})

			It("returns the error that occurred when reading the body", func() {
				testErr := errors.New("testErr")
				request.Body.(*mockBody).readErr = testErr

				var doRsp *http.Response
				var doErr error
				var doReturned bool
				go func() {
					doRsp, doErr = client.Do(request)
					doReturned = true
				}()
				Eventually(func() bool { return doReturned }).Should(BeTrue())
				Expect(doErr).To(MatchError(testErr))
				Expect(doRsp).To(BeNil())
				Expect(request.Body.(*mockBody).closed).To(BeTrue())
			})

			It("returns the error that occurred when closing the body", func() {
				testErr := errors.New("testErr")
				request.Body.(*mockBody).closeErr = testErr

				var doRsp *http.Response
				var doErr error
				var doReturned bool
				go func() {
					doRsp, doErr = client.Do(request)
					doReturned = true
				}()
				Eventually(func() bool { return doReturned }).Should(BeTrue())
				Expect(doErr).To(MatchError(testErr))
				Expect(doRsp).To(BeNil())
				Expect(request.Body.(*mockBody).closed).To(BeTrue())
			})
		})

		Context("gzip compression", func() {
			var gzippedData []byte // a gzipped foobar
			var response *http.Response

			BeforeEach(func() {
				var b bytes.Buffer
				w := gzip.NewWriter(&b)
				w.Write([]byte("foobar"))
				w.Close()
				gzippedData = b.Bytes()
				response = &http.Response{
					StatusCode: 200,
					Header:     http.Header{"Content-Length": []string{"1000"}},
				}
			})

			It("adds the gzip header to requests", func() {
				var doRsp *http.Response
				var doErr error
				go func() { doRsp, doErr = client.Do(request) }()

				Eventually(func() chan *http.Response { return client.responses[5] }).ShouldNot(BeNil())
				dataStream.dataToRead.Write(gzippedData)
				response.Header.Add("Content-Encoding", "gzip")
				client.responses[5] <- response
				Eventually(func() *http.Response { return doRsp }).ShouldNot(BeNil())
				Expect(doErr).ToNot(HaveOccurred())
				headers := getHeaderFields(getRequest(headerStream.dataWritten.Bytes()))
				Expect(headers).To(HaveKeyWithValue("accept-encoding", "gzip"))
				Expect(doRsp.ContentLength).To(BeEquivalentTo(-1))
				Expect(doRsp.Header.Get("Content-Encoding")).To(BeEmpty())
				Expect(doRsp.Header.Get("Content-Length")).To(BeEmpty())
				data := make([]byte, 6)
				doRsp.Body.Read(data)
				Expect(data).To(Equal([]byte("foobar")))
			})

			It("doesn't add gzip if the header disable it", func() {
				quicTransport.DisableCompression = true
				var doErr error
				go func() { _, doErr = client.Do(request) }()

				Eventually(func() chan *http.Response { return client.responses[5] }).ShouldNot(BeNil())
				Expect(doErr).ToNot(HaveOccurred())
				Eventually(func() []byte { return headerStream.dataWritten.Bytes() }).ShouldNot(BeEmpty())
				headers := getHeaderFields(getRequest(headerStream.dataWritten.Bytes()))
				Expect(headers).ToNot(HaveKey("accept-encoding"))
			})

			It("only decompresses the response if the response contains the right content-encoding header", func() {
				var doRsp *http.Response
				var doErr error
				go func() { doRsp, doErr = client.Do(request) }()

				Eventually(func() chan *http.Response { return client.responses[5] }).ShouldNot(BeNil())
				dataStream.dataToRead.Write([]byte("not gzipped"))
				client.responses[5] <- response
				Eventually(func() *http.Response { return doRsp }).ShouldNot(BeNil())
				Expect(doErr).ToNot(HaveOccurred())
				headers := getHeaderFields(getRequest(headerStream.dataWritten.Bytes()))
				Expect(headers).To(HaveKeyWithValue("accept-encoding", "gzip"))
				data := make([]byte, 11)
				doRsp.Body.Read(data)
				Expect(doRsp.ContentLength).ToNot(BeEquivalentTo(-1))
				Expect(data).To(Equal([]byte("not gzipped")))
			})

			It("doesn't add the gzip header for requests that have the accept-enconding set", func() {
				request.Header.Add("accept-encoding", "gzip")
				var doRsp *http.Response
				var doErr error
				go func() { doRsp, doErr = client.Do(request) }()

				Eventually(func() chan *http.Response { return client.responses[5] }).ShouldNot(BeNil())
				dataStream.dataToRead.Write([]byte("gzipped data"))
				client.responses[5] <- response
				Eventually(func() *http.Response { return doRsp }).ShouldNot(BeNil())
				Expect(doErr).ToNot(HaveOccurred())
				headers := getHeaderFields(getRequest(headerStream.dataWritten.Bytes()))
				Expect(headers).To(HaveKeyWithValue("accept-encoding", "gzip"))
				data := make([]byte, 12)
				doRsp.Body.Read(data)
				Expect(doRsp.ContentLength).ToNot(BeEquivalentTo(-1))
				Expect(data).To(Equal([]byte("gzipped data")))
			})
		})

		Context("handling the header stream", func() {
			var h2framer *http2.Framer

			BeforeEach(func() {
				h2framer = http2.NewFramer(&headerStream.dataToRead, nil)
				client.responses[23] = make(chan *http.Response)
			})

			It("reads header values from a response", func() {
				// Taken from https://http2.github.io/http2-spec/compression.html#request.examples.with.huffman.coding
				data := []byte{0x48, 0x03, 0x33, 0x30, 0x32, 0x58, 0x07, 0x70, 0x72, 0x69, 0x76, 0x61, 0x74, 0x65, 0x61, 0x1d, 0x4d, 0x6f, 0x6e, 0x2c, 0x20, 0x32, 0x31, 0x20, 0x4f, 0x63, 0x74, 0x20, 0x32, 0x30, 0x31, 0x33, 0x20, 0x32, 0x30, 0x3a, 0x31, 0x33, 0x3a, 0x32, 0x31, 0x20, 0x47, 0x4d, 0x54, 0x6e, 0x17, 0x68, 0x74, 0x74, 0x70, 0x73, 0x3a, 0x2f, 0x2f, 0x77, 0x77, 0x77, 0x2e, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d}
				headerStream.dataToRead.Write([]byte{0x0, 0x0, byte(len(data)), 0x1, 0x5, 0x0, 0x0, 0x0, 23})
				headerStream.dataToRead.Write(data)
				go client.handleHeaderStream()
				var rsp *http.Response
				Eventually(client.responses[23]).Should(Receive(&rsp))
				Expect(rsp).ToNot(BeNil())
				Expect(rsp.Proto).To(Equal("HTTP/2.0"))
				Expect(rsp.ProtoMajor).To(BeEquivalentTo(2))
				Expect(rsp.StatusCode).To(BeEquivalentTo(302))
				Expect(rsp.Status).To(Equal("302 Found"))
				Expect(rsp.Header).To(HaveKeyWithValue("Location", []string{"https://www.example.com"}))
				Expect(rsp.Header).To(HaveKeyWithValue("Cache-Control", []string{"private"}))
			})

			It("errors if the H2 frame is not a HeadersFrame", func() {
				h2framer.WritePing(true, [8]byte{0, 0, 0, 0, 0, 0, 0, 0})

				var handlerReturned bool
				go func() {
					client.handleHeaderStream()
					handlerReturned = true
				}()

				var rsp *http.Response
				Eventually(client.responses[23]).Should(Receive(&rsp))
				Expect(rsp).To(BeNil())
				Expect(client.headerErr).To(MatchError(qerr.Error(qerr.InvalidHeadersStreamData, "not a headers frame")))
				Eventually(func() bool { return handlerReturned }).Should(BeTrue())
			})

			It("errors if it can't read the HPACK encoded header fields", func() {
				h2framer.WriteHeaders(http2.HeadersFrameParam{
					StreamID:      23,
					EndHeaders:    true,
					BlockFragment: []byte("invalid HPACK data"),
				})

				var handlerReturned bool
				go func() {
					client.handleHeaderStream()
					handlerReturned = true
				}()

				var rsp *http.Response
				Eventually(client.responses[23]).Should(Receive(&rsp))
				Expect(rsp).To(BeNil())
				Expect(client.headerErr).To(MatchError(qerr.Error(qerr.InvalidHeadersStreamData, "cannot read header fields")))
				Eventually(func() bool { return handlerReturned }).Should(BeTrue())
			})
		})
	})
})
