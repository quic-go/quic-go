package http3

import (
	"net/http"
	"net/url"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/quic-go/qpack"
)

var _ = Describe("Request", func() {
	It("populates requests", func() {
		headers := []qpack.HeaderField{
			{Name: ":path", Value: "/foo"},
			{Name: ":authority", Value: "quic.clemente.io"},
			{Name: ":method", Value: "GET"},
			{Name: "content-length", Value: "42"},
		}
		req, err := requestFromHeaders(headers)
		Expect(err).NotTo(HaveOccurred())
		Expect(req.Method).To(Equal("GET"))
		Expect(req.URL.Path).To(Equal("/foo"))
		Expect(req.URL.Host).To(BeEmpty())
		Expect(req.Proto).To(Equal("HTTP/3.0"))
		Expect(req.ProtoMajor).To(Equal(3))
		Expect(req.ProtoMinor).To(BeZero())
		Expect(req.ContentLength).To(Equal(int64(42)))
		Expect(req.Header).To(HaveLen(1))
		Expect(req.Header.Get("Content-Length")).To(Equal("42"))
		Expect(req.Body).To(BeNil())
		Expect(req.Host).To(Equal("quic.clemente.io"))
		Expect(req.RequestURI).To(Equal("/foo"))
	})

	It("rejects upper-case fields", func() {
		headers := []qpack.HeaderField{
			{Name: ":path", Value: "/foo"},
			{Name: ":authority", Value: "quic.clemente.io"},
			{Name: ":method", Value: "GET"},
			{Name: "Content-Length", Value: "42"},
		}
		_, err := requestFromHeaders(headers)
		Expect(err).To(MatchError("header field is not lower-case: Content-Length"))
	})

	It("rejects unknown pseudo headers", func() {
		headers := []qpack.HeaderField{
			{Name: ":path", Value: "/foo"},
			{Name: ":authority", Value: "quic.clemente.io"},
			{Name: ":method", Value: "GET"},
			{Name: ":foo", Value: "bar"},
		}
		_, err := requestFromHeaders(headers)
		Expect(err).To(MatchError("unknown pseudo header: :foo"))
	})

	It("rejects invalid field names", func() {
		headers := []qpack.HeaderField{
			{Name: ":path", Value: "/foo"},
			{Name: ":authority", Value: "quic.clemente.io"},
			{Name: ":method", Value: "GET"},
			{Name: "@", Value: "42"},
		}
		_, err := requestFromHeaders(headers)
		Expect(err).To(MatchError(`invalid header field name: "@"`))
	})

	It("rejects invalid field values", func() {
		headers := []qpack.HeaderField{
			{Name: ":path", Value: "/foo"},
			{Name: ":authority", Value: "quic.clemente.io"},
			{Name: ":method", Value: "GET"},
			{Name: "content", Value: "\n"},
		}
		_, err := requestFromHeaders(headers)
		Expect(err).To(MatchError(`invalid header field value for content: "\n"`))
	})

	It("rejects pseudo header fields after regular header fields", func() {
		headers := []qpack.HeaderField{
			{Name: ":path", Value: "/foo"},
			{Name: "content-length", Value: "42"},
			{Name: ":authority", Value: "quic.clemente.io"},
			{Name: ":method", Value: "GET"},
		}
		_, err := requestFromHeaders(headers)
		Expect(err).To(MatchError("received pseudo header :authority after a regular header field"))
	})

	It("rejects negative Content-Length values", func() {
		headers := []qpack.HeaderField{
			{Name: ":path", Value: "/foo"},
			{Name: ":authority", Value: "quic.clemente.io"},
			{Name: ":method", Value: "GET"},
			{Name: "content-length", Value: "-42"},
		}
		_, err := requestFromHeaders(headers)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("invalid content length"))
	})

	It("rejects multiple Content-Length headers, if they differ", func() {
		headers := []qpack.HeaderField{
			{Name: ":path", Value: "/foo"},
			{Name: ":authority", Value: "quic.clemente.io"},
			{Name: ":method", Value: "GET"},
			{Name: "content-length", Value: "42"},
			{Name: "content-length", Value: "1337"},
		}
		_, err := requestFromHeaders(headers)
		Expect(err).To(MatchError("contradicting content lengths (42 and 1337)"))
	})

	It("deduplicates multiple Content-Length headers, if they're the same", func() {
		headers := []qpack.HeaderField{
			{Name: ":path", Value: "/foo"},
			{Name: ":authority", Value: "quic.clemente.io"},
			{Name: ":method", Value: "GET"},
			{Name: "content-length", Value: "42"},
			{Name: "content-length", Value: "42"},
		}
		req, err := requestFromHeaders(headers)
		Expect(err).ToNot(HaveOccurred())
		Expect(req.ContentLength).To(Equal(int64(42)))
		Expect(req.Header.Get("Content-Length")).To(Equal("42"))
	})

	It("rejects pseudo header fields defined for responses", func() {
		headers := []qpack.HeaderField{
			{Name: ":path", Value: "/foo"},
			{Name: ":authority", Value: "quic.clemente.io"},
			{Name: ":method", Value: "GET"},
			{Name: ":status", Value: "404"},
		}
		_, err := requestFromHeaders(headers)
		Expect(err).To(MatchError("invalid request pseudo header: :status"))
	})

	It("parses path with leading double slashes", func() {
		headers := []qpack.HeaderField{
			{Name: ":path", Value: "//foo"},
			{Name: ":authority", Value: "quic.clemente.io"},
			{Name: ":method", Value: "GET"},
		}
		req, err := requestFromHeaders(headers)
		Expect(err).NotTo(HaveOccurred())
		Expect(req.Header).To(BeEmpty())
		Expect(req.Body).To(BeNil())
		Expect(req.URL.Path).To(Equal("//foo"))
		Expect(req.URL.Host).To(BeEmpty())
		Expect(req.Host).To(Equal("quic.clemente.io"))
		Expect(req.RequestURI).To(Equal("//foo"))
	})

	It("concatenates the cookie headers", func() {
		headers := []qpack.HeaderField{
			{Name: ":path", Value: "/foo"},
			{Name: ":authority", Value: "quic.clemente.io"},
			{Name: ":method", Value: "GET"},
			{Name: "cookie", Value: "cookie1=foobar1"},
			{Name: "cookie", Value: "cookie2=foobar2"},
		}
		req, err := requestFromHeaders(headers)
		Expect(err).NotTo(HaveOccurred())
		Expect(req.Header).To(Equal(http.Header{
			"Cookie": []string{"cookie1=foobar1; cookie2=foobar2"},
		}))
	})

	It("handles Other headers", func() {
		headers := []qpack.HeaderField{
			{Name: ":path", Value: "/foo"},
			{Name: ":authority", Value: "quic.clemente.io"},
			{Name: ":method", Value: "GET"},
			{Name: "cache-control", Value: "max-age=0"},
			{Name: "duplicate-header", Value: "1"},
			{Name: "duplicate-header", Value: "2"},
		}
		req, err := requestFromHeaders(headers)
		Expect(err).NotTo(HaveOccurred())
		Expect(req.Header).To(Equal(http.Header{
			"Cache-Control":    []string{"max-age=0"},
			"Duplicate-Header": []string{"1", "2"},
		}))
	})

	It("errors with missing path", func() {
		headers := []qpack.HeaderField{
			{Name: ":authority", Value: "quic.clemente.io"},
			{Name: ":method", Value: "GET"},
		}
		_, err := requestFromHeaders(headers)
		Expect(err).To(MatchError(":path, :authority and :method must not be empty"))
	})

	It("errors with missing method", func() {
		headers := []qpack.HeaderField{
			{Name: ":path", Value: "/foo"},
			{Name: ":authority", Value: "quic.clemente.io"},
		}
		_, err := requestFromHeaders(headers)
		Expect(err).To(MatchError(":path, :authority and :method must not be empty"))
	})

	It("errors with missing authority", func() {
		headers := []qpack.HeaderField{
			{Name: ":path", Value: "/foo"},
			{Name: ":method", Value: "GET"},
		}
		_, err := requestFromHeaders(headers)
		Expect(err).To(MatchError(":path, :authority and :method must not be empty"))
	})

	Context("regular HTTP CONNECT", func() {
		It("handles CONNECT method", func() {
			headers := []qpack.HeaderField{
				{Name: ":authority", Value: "quic.clemente.io"},
				{Name: ":method", Value: http.MethodConnect},
			}
			req, err := requestFromHeaders(headers)
			Expect(err).NotTo(HaveOccurred())
			Expect(req.Method).To(Equal(http.MethodConnect))
			Expect(req.RequestURI).To(Equal("quic.clemente.io"))
		})

		It("errors with missing authority in CONNECT method", func() {
			headers := []qpack.HeaderField{
				{Name: ":method", Value: http.MethodConnect},
			}
			_, err := requestFromHeaders(headers)
			Expect(err).To(MatchError(":path must be empty and :authority must not be empty"))
		})

		It("errors with extra path in CONNECT method", func() {
			headers := []qpack.HeaderField{
				{Name: ":path", Value: "/foo"},
				{Name: ":authority", Value: "quic.clemente.io"},
				{Name: ":method", Value: http.MethodConnect},
			}
			_, err := requestFromHeaders(headers)
			Expect(err).To(MatchError(":path must be empty and :authority must not be empty"))
		})
	})

	Context("Extended CONNECT", func() {
		It("handles Extended CONNECT method", func() {
			headers := []qpack.HeaderField{
				{Name: ":protocol", Value: "webtransport"},
				{Name: ":scheme", Value: "ftp"},
				{Name: ":method", Value: http.MethodConnect},
				{Name: ":authority", Value: "quic.clemente.io"},
				{Name: ":path", Value: "/foo?val=1337"},
			}
			req, err := requestFromHeaders(headers)
			Expect(err).NotTo(HaveOccurred())
			Expect(req.Method).To(Equal(http.MethodConnect))
			Expect(req.Proto).To(Equal("webtransport"))
			Expect(req.URL.String()).To(Equal("ftp://quic.clemente.io/foo?val=1337"))
			Expect(req.URL.Query().Get("val")).To(Equal("1337"))
		})

		It("errors with missing scheme", func() {
			headers := []qpack.HeaderField{
				{Name: ":protocol", Value: "webtransport"},
				{Name: ":method", Value: http.MethodConnect},
				{Name: ":authority", Value: "quic.clemente.io"},
				{Name: ":path", Value: "/foo"},
			}
			_, err := requestFromHeaders(headers)
			Expect(err).To(MatchError("extended CONNECT: :scheme, :path and :authority must not be empty"))
		})
	})

	Context("extracting the hostname from a request", func() {
		var url *url.URL

		BeforeEach(func() {
			var err error
			url, err = url.Parse("https://quic.clemente.io:1337")
			Expect(err).ToNot(HaveOccurred())
		})

		It("uses req.URL.Host", func() {
			req := &http.Request{URL: url}
			Expect(hostnameFromRequest(req)).To(Equal("quic.clemente.io:1337"))
		})

		It("uses req.URL.Host even if req.Host is available", func() {
			req := &http.Request{
				Host: "www.example.org",
				URL:  url,
			}
			Expect(hostnameFromRequest(req)).To(Equal("quic.clemente.io:1337"))
		})

		It("returns an empty hostname if nothing is set", func() {
			Expect(hostnameFromRequest(&http.Request{})).To(BeEmpty())
		})
	})
})

var _ = Describe("Response", func() {
	It("populates responses", func() {
		headers := []qpack.HeaderField{
			{Name: ":status", Value: "200"},
			{Name: "content-length", Value: "42"},
		}
		rsp, err := responseFromHeaders(headers)
		Expect(err).NotTo(HaveOccurred())
		Expect(rsp.Proto).To(Equal("HTTP/3.0"))
		Expect(rsp.ProtoMajor).To(Equal(3))
		Expect(rsp.ProtoMinor).To(BeZero())
		Expect(rsp.ContentLength).To(Equal(int64(42)))
		Expect(rsp.Header).To(HaveLen(1))
		Expect(rsp.Header.Get("Content-Length")).To(Equal("42"))
		Expect(rsp.Body).To(BeNil())
		Expect(rsp.StatusCode).To(BeEquivalentTo(200))
		Expect(rsp.Status).To(Equal("200 OK"))
	})

	It("rejects pseudo header fields after regular header fields", func() {
		headers := []qpack.HeaderField{
			{Name: "content-length", Value: "42"},
			{Name: ":status", Value: "200"},
		}
		_, err := responseFromHeaders(headers)
		Expect(err).To(MatchError("received pseudo header :status after a regular header field"))
	})

	It("rejects response with no status field", func() {
		headers := []qpack.HeaderField{
			{Name: "content-length", Value: "42"},
		}
		_, err := responseFromHeaders(headers)
		Expect(err).To(MatchError("missing status field"))
	})

	It("rejects invalid status codes", func() {
		headers := []qpack.HeaderField{
			{Name: ":status", Value: "foobar"},
			{Name: "content-length", Value: "42"},
		}
		_, err := responseFromHeaders(headers)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("invalid status code"))
	})

	It("rejects pseudo header fields defined for requests", func() {
		headers := []qpack.HeaderField{
			{Name: ":status", Value: "404"},
			{Name: ":method", Value: "GET"},
		}
		_, err := responseFromHeaders(headers)
		Expect(err).To(MatchError("invalid response pseudo header: :method"))
	})
})
