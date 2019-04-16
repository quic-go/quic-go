package http3

import (
	"bytes"
	"io"
	"net/http"
	"strconv"

	"github.com/marten-seemann/qpack"

	"github.com/golang/mock/gomock"
	mockquic "github.com/lucas-clemente/quic-go/internal/mocks/quic"
	"github.com/lucas-clemente/quic-go/internal/utils"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Request Writer", func() {
	var (
		rw     *requestWriter
		str    *mockquic.MockStream
		strBuf *bytes.Buffer
	)

	decode := func(str io.Reader) map[string]string {
		frame, err := parseNextFrame(str)
		Expect(err).ToNot(HaveOccurred())
		Expect(frame).To(BeAssignableToTypeOf(&headersFrame{}))
		headersFrame := frame.(*headersFrame)
		data := make([]byte, headersFrame.Length)
		_, err = io.ReadFull(str, data)
		Expect(err).ToNot(HaveOccurred())
		decoder := qpack.NewDecoder(nil)
		hfs, err := decoder.DecodeFull(data)
		Expect(err).ToNot(HaveOccurred())
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
		req, err := http.NewRequest("GET", "https://quic.clemente.io/index.html?foo=bar", nil)
		Expect(err).ToNot(HaveOccurred())
		Expect(rw.WriteRequest(str, req, false)).To(Succeed())
		headerFields := decode(strBuf)
		Expect(headerFields).To(HaveKeyWithValue(":authority", "quic.clemente.io"))
		Expect(headerFields).To(HaveKeyWithValue(":method", "GET"))
		Expect(headerFields).To(HaveKeyWithValue(":path", "/index.html?foo=bar"))
		Expect(headerFields).To(HaveKeyWithValue(":scheme", "https"))
		Expect(headerFields).ToNot(HaveKey("accept-encoding"))
	})

	It("writes a POST request", func() {
		closed := make(chan struct{})
		str.EXPECT().Close().Do(func() { close(closed) })
		postData := bytes.NewReader([]byte("foobar"))
		req, err := http.NewRequest("POST", "https://quic.clemente.io/upload.html", postData)
		Expect(err).ToNot(HaveOccurred())
		Expect(rw.WriteRequest(str, req, false)).To(Succeed())
		headerFields := decode(strBuf)
		Expect(headerFields).To(HaveKeyWithValue(":method", "POST"))
		Expect(headerFields).To(HaveKey("content-length"))
		contentLength, err := strconv.Atoi(headerFields["content-length"])
		Expect(err).ToNot(HaveOccurred())
		Expect(contentLength).To(BeNumerically(">", 0))

		Eventually(closed).Should(BeClosed())
		frame, err := parseNextFrame(strBuf)
		Expect(err).ToNot(HaveOccurred())
		Expect(frame).To(BeAssignableToTypeOf(&dataFrame{}))
		Expect(frame.(*dataFrame).Length).To(BeEquivalentTo(6))
	})

	It("sends cookies", func() {
		str.EXPECT().Close()
		req, err := http.NewRequest("GET", "https://quic.clemente.io/", nil)
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
		Expect(rw.WriteRequest(str, req, false)).To(Succeed())
		headerFields := decode(strBuf)
		Expect(headerFields).To(HaveKeyWithValue("cookie", `Cookie #1="Value #1"; Cookie #2="Value #2"`))
	})

	It("adds the header for gzip support", func() {
		str.EXPECT().Close()
		req, err := http.NewRequest("GET", "https://quic.clemente.io/", nil)
		Expect(err).ToNot(HaveOccurred())
		Expect(rw.WriteRequest(str, req, true)).To(Succeed())
		headerFields := decode(strBuf)
		Expect(headerFields).To(HaveKeyWithValue("accept-encoding", "gzip"))
	})
})
