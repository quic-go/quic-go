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
