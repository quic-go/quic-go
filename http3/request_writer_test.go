package http3

import (
	"bytes"
	"io"
	"net/http"

	mockquic "github.com/quic-go/quic-go/internal/mocks/quic"
	"github.com/quic-go/quic-go/internal/utils"

	"github.com/golang/mock/gomock"
	"github.com/quic-go/qpack"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Request Writer", func() {
	var (
		rw     *requestWriter
		str    *mockquic.MockStream
		strBuf *bytes.Buffer
	)

	decode := func(str io.Reader) map[string]string {
		frame, err := parseNextFrame(str, nil)
		ExpectWithOffset(1, err).ToNot(HaveOccurred())
		ExpectWithOffset(1, frame).To(BeAssignableToTypeOf(&headersFrame{}))
		headersFrame := frame.(*headersFrame)
		data := make([]byte, headersFrame.Length)
		_, err = io.ReadFull(str, data)
		ExpectWithOffset(1, err).ToNot(HaveOccurred())
		decoder := qpack.NewDecoder(nil)
		hfs, err := decoder.DecodeFull(data)
		ExpectWithOffset(1, err).ToNot(HaveOccurred())
		values := make(map[string]string)
		for _, hf := range hfs {
			values[hf.Name] = hf.Value
		}
		return values
	}

	BeforeEach(func() {
		rw = newRequestWriter(utils.DefaultLogger)
		strBuf = &bytes.Buffer{}
		str = mockquic.NewMockStream(mockCtrl)
		str.EXPECT().Write(gomock.Any()).DoAndReturn(strBuf.Write).AnyTimes()
	})

	It("writes a GET request", func() {
		req, err := http.NewRequest(http.MethodGet, "https://quic.clemente.io/index.html?foo=bar", nil)
		Expect(err).ToNot(HaveOccurred())
		Expect(rw.WriteRequestHeader(str, req, false)).To(Succeed())
		headerFields := decode(strBuf)
		Expect(headerFields).To(HaveKeyWithValue(":authority", "quic.clemente.io"))
		Expect(headerFields).To(HaveKeyWithValue(":method", "GET"))
		Expect(headerFields).To(HaveKeyWithValue(":path", "/index.html?foo=bar"))
		Expect(headerFields).To(HaveKeyWithValue(":scheme", "https"))
		Expect(headerFields).ToNot(HaveKey("accept-encoding"))
	})

	It("rejects invalid host headers", func() {
		req, err := http.NewRequest(http.MethodGet, "https://quic.clemente.io/index.html?foo=bar", nil)
		Expect(err).ToNot(HaveOccurred())
		req.Host = "foo@bar" // @ is invalid
		Expect(rw.WriteRequestHeader(str, req, false)).To(MatchError("http3: invalid Host header"))
	})

	It("sends cookies", func() {
		req, err := http.NewRequest(http.MethodGet, "https://quic.clemente.io/", nil)
		Expect(err).ToNot(HaveOccurred())
		cookie1 := &http.Cookie{
			Name:  "Cookie #1",
			Value: "Value #1",
		}
		cookie2 := &http.Cookie{
			Name:  "Cookie #2",
			Value: "Value #2",
		}
		req.AddCookie(cookie1)
		req.AddCookie(cookie2)
		Expect(rw.WriteRequestHeader(str, req, false)).To(Succeed())
		headerFields := decode(strBuf)
		Expect(headerFields).To(HaveKeyWithValue("cookie", `Cookie #1="Value #1"; Cookie #2="Value #2"`))
	})

	It("adds the header for gzip support", func() {
		req, err := http.NewRequest(http.MethodGet, "https://quic.clemente.io/", nil)
		Expect(err).ToNot(HaveOccurred())
		Expect(rw.WriteRequestHeader(str, req, true)).To(Succeed())
		headerFields := decode(strBuf)
		Expect(headerFields).To(HaveKeyWithValue("accept-encoding", "gzip"))
	})

	It("writes a CONNECT request", func() {
		req, err := http.NewRequest(http.MethodConnect, "https://quic.clemente.io/", nil)
		Expect(err).ToNot(HaveOccurred())
		Expect(rw.WriteRequestHeader(str, req, false)).To(Succeed())
		headerFields := decode(strBuf)
		Expect(headerFields).To(HaveKeyWithValue(":method", "CONNECT"))
		Expect(headerFields).To(HaveKeyWithValue(":authority", "quic.clemente.io"))
		Expect(headerFields).ToNot(HaveKey(":path"))
		Expect(headerFields).ToNot(HaveKey(":scheme"))
		Expect(headerFields).ToNot(HaveKey(":protocol"))
	})

	It("writes an Extended CONNECT request", func() {
		req, err := http.NewRequest(http.MethodConnect, "https://quic.clemente.io/foobar", nil)
		Expect(err).ToNot(HaveOccurred())
		req.Proto = "webtransport"
		Expect(rw.WriteRequestHeader(str, req, false)).To(Succeed())
		headerFields := decode(strBuf)
		Expect(headerFields).To(HaveKeyWithValue(":authority", "quic.clemente.io"))
		Expect(headerFields).To(HaveKeyWithValue(":method", "CONNECT"))
		Expect(headerFields).To(HaveKeyWithValue(":path", "/foobar"))
		Expect(headerFields).To(HaveKeyWithValue(":scheme", "https"))
		Expect(headerFields).To(HaveKeyWithValue(":protocol", "webtransport"))
	})
})
