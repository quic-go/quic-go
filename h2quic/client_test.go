package h2quic

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net/http"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"

	quic "github.com/lucas-clemente/quic-go"
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/qerr"

	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Client", func() {
	var (
		client       *client
		session      *mockSession
		headerStream *mockStream
		req          *http.Request
		origDialAddr = dialAddr
	)

	BeforeEach(func() {
		origDialAddr = dialAddr
		hostname := "quic.clemente.io:1337"
		client = newClient(hostname, nil, &roundTripperOpts{}, nil)
		Expect(client.hostname).To(Equal(hostname))
		session = &mockSession{}
		session.ctx, session.ctxCancel = context.WithCancel(context.Background())
		client.session = session

		headerStream = newMockStream(3)
		client.headerStream = headerStream
		client.requestWriter = newRequestWriter(headerStream)
		var err error
		req, err = http.NewRequest("GET", "https://localhost:1337", nil)
		Expect(err).ToNot(HaveOccurred())
	})

	AfterEach(func() {
		dialAddr = origDialAddr
	})

	It("saves the TLS config", func() {
		tlsConf := &tls.Config{InsecureSkipVerify: true}
		client = newClient("", tlsConf, &roundTripperOpts{}, nil)
		Expect(client.tlsConf).To(Equal(tlsConf))
	})

	It("saves the QUIC config", func() {
		quicConf := &quic.Config{HandshakeTimeout: time.Nanosecond}
		client = newClient("", &tls.Config{}, &roundTripperOpts{}, quicConf)
		Expect(client.config).To(Equal(quicConf))
	})

	It("uses the default QUIC config if none is give", func() {
		client = newClient("", &tls.Config{}, &roundTripperOpts{}, nil)
		Expect(client.config).ToNot(BeNil())
		Expect(client.config).To(Equal(defaultQuicConfig))
	})

	It("adds the port to the hostname, if none is given", func() {
		client = newClient("quic.clemente.io", nil, &roundTripperOpts{}, nil)
		Expect(client.hostname).To(Equal("quic.clemente.io:443"))
	})

	It("dials", func(done Done) {
		client = newClient("localhost:1337", nil, &roundTripperOpts{}, nil)
		session.streamsToOpen = []quic.Stream{newMockStream(3), newMockStream(5)}
		dialAddr = func(hostname string, _ *tls.Config, _ *quic.Config) (quic.Session, error) {
			return session, nil
		}
		close(headerStream.unblockRead)
		go client.RoundTrip(req)
		Eventually(func() quic.Session { return client.session }).Should(Equal(session))
		close(done)
	}, 2)

	It("errors when dialing fails", func() {
		testErr := errors.New("handshake error")
		client = newClient("localhost:1337", nil, &roundTripperOpts{}, nil)
		dialAddr = func(hostname string, _ *tls.Config, _ *quic.Config) (quic.Session, error) {
			return nil, testErr
		}
		_, err := client.RoundTrip(req)
		Expect(err).To(MatchError(testErr))
	})

	It("errors if the header stream has the wrong stream ID", func() {
		client = newClient("localhost:1337", nil, &roundTripperOpts{}, nil)
		session.streamsToOpen = []quic.Stream{&mockStream{id: 2}}
		dialAddr = func(hostname string, _ *tls.Config, _ *quic.Config) (quic.Session, error) {
			return session, nil
		}
		_, err := client.RoundTrip(req)
		Expect(err).To(MatchError("h2quic Client BUG: StreamID of Header Stream is not 3"))
	})

	It("errors if it can't open a stream", func() {
		testErr := errors.New("you shall not pass")
		client = newClient("localhost:1337", nil, &roundTripperOpts{}, nil)
		session.streamOpenErr = testErr
		dialAddr = func(hostname string, _ *tls.Config, _ *quic.Config) (quic.Session, error) {
			return session, nil
		}
		_, err := client.RoundTrip(req)
		Expect(err).To(MatchError(testErr))
	})

	It("returns a request when dial fails", func() {
		testErr := errors.New("dial error")
		dialAddr = func(hostname string, _ *tls.Config, _ *quic.Config) (quic.Session, error) {
			return nil, testErr
		}
		request, err := http.NewRequest("https", "https://quic.clemente.io:1337/file1.dat", nil)
		Expect(err).ToNot(HaveOccurred())

		var doErr error
		go func() {
			_, doErr = client.RoundTrip(request)
		}()
		_, err = client.RoundTrip(request)
		Expect(err).To(MatchError(testErr))
		Eventually(func() error { return doErr }).Should(MatchError(testErr))
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
			dialAddr = func(hostname string, _ *tls.Config, _ *quic.Config) (quic.Session, error) {
				return session, nil
			}
			dataStream = newMockStream(5)
			session.streamsToOpen = []quic.Stream{headerStream, dataStream}
			request, err = http.NewRequest("https", "https://quic.clemente.io:1337/file1.dat", nil)
			Expect(err).ToNot(HaveOccurred())
		})

		It("does a request", func(done Done) {
			var doRsp *http.Response
			var doErr error
			var doReturned bool
			go func() {
				doRsp, doErr = client.RoundTrip(request)
				doReturned = true
			}()

			Eventually(func() []byte { return headerStream.dataWritten.Bytes() }).ShouldNot(BeEmpty())
			Eventually(func() map[protocol.StreamID]chan *http.Response { return client.responses }).Should(HaveKey(protocol.StreamID(5)))
			rsp := &http.Response{
				Status:     "418 I'm a teapot",
				StatusCode: 418,
			}
			Expect(client.responses[5]).ToNot(BeClosed())
			Expect(client.headerErrored).ToNot(BeClosed())
			client.responses[5] <- rsp
			Eventually(func() bool { return doReturned }).Should(BeTrue())
			Expect(doErr).ToNot(HaveOccurred())
			Expect(doRsp).To(Equal(rsp))
			Expect(doRsp.Body).To(Equal(dataStream))
			Expect(doRsp.ContentLength).To(BeEquivalentTo(-1))
			Expect(doRsp.Request).To(Equal(request))

			close(done)
		})

		It("closes the quic client when encountering an error on the header stream", func(done Done) {
			headerStream.dataToRead.Write(bytes.Repeat([]byte{0}, 100))
			var doReturned bool
			go func() {
				defer GinkgoRecover()
				var err error
				rsp, err := client.RoundTrip(request)
				Expect(err).To(MatchError(client.headerErr))
				Expect(rsp).To(BeNil())
				doReturned = true
			}()

			Eventually(func() bool { return doReturned }).Should(BeTrue())
			Expect(client.headerErr).To(MatchError(qerr.Error(qerr.HeadersStreamDataDecompressFailure, "cannot read frame")))
			Expect(client.session.(*mockSession).closedWithError).To(MatchError(client.headerErr))
			close(done)
		}, 2)

		It("returns subsequent request if there was an error on the header stream before", func(done Done) {
			expectedErr := qerr.Error(qerr.HeadersStreamDataDecompressFailure, "cannot read frame")
			session.streamsToOpen = []quic.Stream{headerStream, dataStream, newMockStream(7)}
			headerStream.dataToRead.Write(bytes.Repeat([]byte{0}, 100))
			var firstReqReturned bool
			go func() {
				defer GinkgoRecover()
				_, err := client.RoundTrip(request)
				Expect(err).To(MatchError(expectedErr))
				firstReqReturned = true
			}()

			Eventually(func() bool { return firstReqReturned }).Should(BeTrue())
			// now that the first request failed due to an error on the header stream, try another request
			_, err := client.RoundTrip(request)
			Expect(err).To(MatchError(expectedErr))
			close(done)
		})

		It("blocks if no stream is available", func() {
			session.streamsToOpen = []quic.Stream{headerStream}
			session.blockOpenStreamSync = true
			var doReturned bool
			go func() {
				defer GinkgoRecover()
				_, err := client.RoundTrip(request)
				Expect(err).ToNot(HaveOccurred())
				doReturned = true
			}()
			go client.handleHeaderStream()

			Consistently(func() bool { return doReturned }).Should(BeFalse())
		})

		Context("validating the address", func() {
			It("refuses to do requests for the wrong host", func() {
				req, err := http.NewRequest("https", "https://quic.clemente.io:1336/foobar.html", nil)
				Expect(err).ToNot(HaveOccurred())
				_, err = client.RoundTrip(req)
				Expect(err).To(MatchError("h2quic Client BUG: RoundTrip called for the wrong client (expected quic.clemente.io:1337, got quic.clemente.io:1336)"))
			})

			It("refuses to do plain HTTP requests", func() {
				req, err := http.NewRequest("https", "http://quic.clemente.io:1337/foobar.html", nil)
				Expect(err).ToNot(HaveOccurred())
				_, err = client.RoundTrip(req)
				Expect(err).To(MatchError("quic http2: unsupported scheme"))
			})

			It("adds the port for request URLs without one", func(done Done) {
				var err error
				client = newClient("quic.clemente.io", nil, &roundTripperOpts{}, nil)
				req, err := http.NewRequest("https", "https://quic.clemente.io/foobar.html", nil)
				Expect(err).ToNot(HaveOccurred())

				var doErr error
				var doReturned bool
				// the client.RoundTrip will block, because the encryption level is still set to Unencrypted
				go func() {
					_, doErr = client.RoundTrip(req)
					doReturned = true
				}()

				Consistently(doReturned).Should(BeFalse())
				Expect(doErr).ToNot(HaveOccurred())
				close(done)
			})
		})

		It("sets the EndStream header for requests without a body", func() {
			go func() { client.RoundTrip(request) }()
			Eventually(func() []byte { return headerStream.dataWritten.Bytes() }).ShouldNot(BeNil())
			mhf := getRequest(headerStream.dataWritten.Bytes())
			Expect(mhf.HeadersFrame.StreamEnded()).To(BeTrue())
		})

		It("sets the EndStream header to false for requests with a body", func() {
			request.Body = &mockBody{}
			go func() { client.RoundTrip(request) }()
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
				// fake a handshake
				client.dialOnce.Do(func() {})
				session.streamsToOpen = []quic.Stream{dataStream}
			})

			It("sends a request", func() {
				var doRsp *http.Response
				var doErr error
				var doReturned bool
				go func() {
					defer GinkgoRecover()
					doRsp, doErr = client.RoundTrip(request)
					Expect(doErr).ToNot(HaveOccurred())
					doReturned = true
				}()
				Eventually(func() chan *http.Response { return client.responses[5] }).ShouldNot(BeNil())
				client.responses[5] <- response
				Eventually(func() bool { return doReturned }).Should(BeTrue())
				Expect(dataStream.dataWritten.Bytes()).To(Equal(requestBody))
				Expect(dataStream.closed).To(BeTrue())
				Expect(request.Body.(*mockBody).closed).To(BeTrue())
				Expect(doRsp).To(Equal(response))
			})

			It("returns the error that occurred when reading the body", func() {
				testErr := errors.New("testErr")
				request.Body.(*mockBody).readErr = testErr

				var doRsp *http.Response
				var doErr error
				var doReturned bool
				go func() {
					doRsp, doErr = client.RoundTrip(request)
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
					doRsp, doErr = client.RoundTrip(request)
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

			It("adds the gzip header to requests", func(done Done) {
				var doRsp *http.Response
				var doErr error
				go func() { doRsp, doErr = client.RoundTrip(request) }()

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
				close(dataStream.unblockRead)
				data := make([]byte, 6)
				_, err := io.ReadFull(doRsp.Body, data)
				Expect(err).ToNot(HaveOccurred())
				Expect(data).To(Equal([]byte("foobar")))
				close(done)
			}, 2)

			It("doesn't add gzip if the header disable it", func() {
				client.opts.DisableCompression = true
				var doErr error
				go func() { _, doErr = client.RoundTrip(request) }()

				Eventually(func() chan *http.Response { return client.responses[5] }).ShouldNot(BeNil())
				Expect(doErr).ToNot(HaveOccurred())
				Eventually(func() []byte { return headerStream.dataWritten.Bytes() }).ShouldNot(BeEmpty())
				headers := getHeaderFields(getRequest(headerStream.dataWritten.Bytes()))
				Expect(headers).ToNot(HaveKey("accept-encoding"))
			})

			It("only decompresses the response if the response contains the right content-encoding header", func() {
				var doRsp *http.Response
				var doErr error
				go func() { doRsp, doErr = client.RoundTrip(request) }()

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
				go func() { doRsp, doErr = client.RoundTrip(request) }()

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

				Eventually(client.headerErrored).Should(BeClosed())
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

				Eventually(client.headerErrored).Should(BeClosed())
				Expect(client.headerErr).To(MatchError(qerr.Error(qerr.InvalidHeadersStreamData, "cannot read header fields")))
				Eventually(func() bool { return handlerReturned }).Should(BeTrue())
			})
		})
	})
})
