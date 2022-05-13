package http3

import (
	"bytes"
	"io"
	"net/http"
	"strconv"

	mockquic "github.com/lucas-clemente/quic-go/internal/mocks/quic"
	"github.com/lucas-clemente/quic-go/internal/utils"

	"github.com/golang/mock/gomock"
	"github.com/marten-seemann/qpack"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

type foobarReader struct{}

func (r *foobarReader) Read(b []byte) (int, error) {
	return copy(b, []byte("foobar")), io.EOF
}

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
		str.EXPECT().Write(gomock.Any()).DoAndReturn(func(p []byte) (int, error) {
			return strBuf.Write(p)
		}).AnyTimes()
	})

	It("writes a GET request", func() {
		str.EXPECT().Close()
		req, err := http.NewRequest(http.MethodGet, "https://quic.clemente.io/index.html?foo=bar", nil)
		Expect(err).ToNot(HaveOccurred())
		Expect(rw.WriteRequest(str, req, false, false)).To(Succeed())
		headerFields := decode(strBuf)
		Expect(headerFields).To(HaveKeyWithValue(":authority", "quic.clemente.io"))
		Expect(headerFields).To(HaveKeyWithValue(":method", "GET"))
		Expect(headerFields).To(HaveKeyWithValue(":path", "/index.html?foo=bar"))
		Expect(headerFields).To(HaveKeyWithValue(":scheme", "https"))
		Expect(headerFields).ToNot(HaveKey("accept-encoding"))
	})

	It("writes a GET request without closing the stream", func() {
		req, err := http.NewRequest(http.MethodGet, "https://quic.clemente.io", nil)
		Expect(err).ToNot(HaveOccurred())
		Expect(rw.WriteRequest(str, req, true, false)).To(Succeed())
		headerFields := decode(strBuf)
		Expect(headerFields).To(HaveKeyWithValue(":authority", "quic.clemente.io"))
	})

	It("writes a POST request", func() {
		closed := make(chan struct{})
		str.EXPECT().Close().Do(func() { close(closed) })
		postData := bytes.NewReader([]byte("foobar"))
		req, err := http.NewRequest(http.MethodPost, "https://quic.clemente.io/upload.html", postData)
		Expect(err).ToNot(HaveOccurred())
		Expect(rw.WriteRequest(str, req, false, false)).To(Succeed())

		Eventually(closed).Should(BeClosed())
		headerFields := decode(strBuf)
		Expect(headerFields).To(HaveKeyWithValue(":method", "POST"))
		Expect(headerFields).To(HaveKey("content-length"))
		contentLength, err := strconv.Atoi(headerFields["content-length"])
		Expect(err).ToNot(HaveOccurred())
		Expect(contentLength).To(BeNumerically(">", 0))

		frame, err := parseNextFrame(strBuf, nil)
		Expect(err).ToNot(HaveOccurred())
		Expect(frame).To(BeAssignableToTypeOf(&dataFrame{}))
		Expect(frame.(*dataFrame).Length).To(BeEquivalentTo(6))
	})

	It("writes a POST request, if the Body returns an EOF immediately", func() {
		closed := make(chan struct{})
		str.EXPECT().Close().Do(func() { close(closed) })
		req, err := http.NewRequest(http.MethodPost, "https://quic.clemente.io/upload.html", &foobarReader{})
		Expect(err).ToNot(HaveOccurred())
		Expect(rw.WriteRequest(str, req, false, false)).To(Succeed())

		Eventually(closed).Should(BeClosed())
		headerFields := decode(strBuf)
		Expect(headerFields).To(HaveKeyWithValue(":method", "POST"))

		frame, err := parseNextFrame(strBuf, nil)
		Expect(err).ToNot(HaveOccurred())
		Expect(frame).To(BeAssignableToTypeOf(&dataFrame{}))
		Expect(frame.(*dataFrame).Length).To(BeEquivalentTo(6))
	})

	It("sends cookies", func() {
		str.EXPECT().Close()
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
		Expect(rw.WriteRequest(str, req, false, false)).To(Succeed())
		headerFields := decode(strBuf)
		Expect(headerFields).To(HaveKeyWithValue("cookie", `Cookie #1="Value #1"; Cookie #2="Value #2"`))
	})

	It("adds the header for gzip support", func() {
		str.EXPECT().Close()
		req, err := http.NewRequest(http.MethodGet, "https://quic.clemente.io/", nil)
		Expect(err).ToNot(HaveOccurred())
		Expect(rw.WriteRequest(str, req, false, true)).To(Succeed())
		headerFields := decode(strBuf)
		Expect(headerFields).To(HaveKeyWithValue("accept-encoding", "gzip"))
	})

	It("writes a CONNECT request", func() {
		str.EXPECT().Close()
		req, err := http.NewRequest(http.MethodConnect, "https://quic.clemente.io/", nil)
		Expect(err).ToNot(HaveOccurred())
		Expect(rw.WriteRequest(str, req, false, false)).To(Succeed())
		headerFields := decode(strBuf)
		Expect(headerFields).To(HaveKeyWithValue(":method", "CONNECT"))
		Expect(headerFields).To(HaveKeyWithValue(":authority", "quic.clemente.io"))
		Expect(headerFields).ToNot(HaveKey(":path"))
		Expect(headerFields).ToNot(HaveKey(":scheme"))
		Expect(headerFields).ToNot(HaveKey(":protocol"))
	})

	It("writes an Extended CONNECT request", func() {
		str.EXPECT().Close()
		req, err := http.NewRequest(http.MethodConnect, "https://quic.clemente.io/foobar", nil)
		Expect(err).ToNot(HaveOccurred())
		req.Proto = "webtransport"
		Expect(rw.WriteRequest(str, req, false, false)).To(Succeed())
		headerFields := decode(strBuf)
		Expect(headerFields).To(HaveKeyWithValue(":authority", "quic.clemente.io"))
		Expect(headerFields).To(HaveKeyWithValue(":method", "CONNECT"))
		Expect(headerFields).To(HaveKeyWithValue(":path", "/foobar"))
		Expect(headerFields).To(HaveKeyWithValue(":scheme", "https"))
		Expect(headerFields).To(HaveKeyWithValue(":protocol", "webtransport"))
	})
})
