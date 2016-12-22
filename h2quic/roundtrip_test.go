package h2quic

import (
	"net/http"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

type mockQuicRoundTripper struct{}

func (m *mockQuicRoundTripper) Do(req *http.Request) (*http.Response, error) {
	return &http.Response{Request: req}, nil
}

type mockBody struct {
	closed bool
}

func (m *mockBody) Read([]byte) (int, error) {
	panic("not implemented")
}

func (m *mockBody) Close() error {
	m.closed = true
	return nil
}

var _ = Describe("RoundTripper", func() {
	var (
		rt   *QuicRoundTripper
		req1 *http.Request
	)

	BeforeEach(func() {
		rt = &QuicRoundTripper{}
		var err error
		req1, err = http.NewRequest("GET", "https://www.example.org/file1.html", nil)
		Expect(err).ToNot(HaveOccurred())
	})

	It("rejects requests without a URL", func() {
		req1.URL = nil
		_, err := rt.RoundTrip(req1)
		Expect(err).To(MatchError("quic: nil Request.URL"))
	})

	It("rejects request without a URL Host", func() {
		req1.URL.Host = ""
		req1.Body = &mockBody{}
		_, err := rt.RoundTrip(req1)
		Expect(err).To(MatchError("quic: no Host in request URL"))
		Expect(req1.Body.(*mockBody).closed).To(BeTrue())
	})

	It("closes the body for rejected requests", func() {
		req1.URL = nil
		req1.Body = &mockBody{}
		_, err := rt.RoundTrip(req1)
		Expect(err).To(MatchError("quic: nil Request.URL"))
		Expect(req1.Body.(*mockBody).closed).To(BeTrue())
	})

	It("rejects requests without a header", func() {
		req1.Header = nil
		_, err := rt.RoundTrip(req1)
		Expect(err).To(MatchError("quic: nil Request.Header"))
	})

	It("reuses existing clients", func() {
		rt.clients = make(map[string]h2quicClient)
		rt.clients["www.example.org:443"] = &mockQuicRoundTripper{}
		rsp, _ := rt.RoundTrip(req1)
		Expect(rsp.Request).To(Equal(req1))
		Expect(rt.clients).To(HaveLen(1))
	})

	It("disable compression", func() {
		Expect(rt.disableCompression()).To(BeFalse())
		rt.DisableCompression = true
		Expect(rt.disableCompression()).To(BeTrue())
	})
})
