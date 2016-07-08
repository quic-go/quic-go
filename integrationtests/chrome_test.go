package integrationtests

import (
	"fmt"
	"io"
	"net/http"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

const nImgs = 200
const imgSize = 40

func init() {
	http.HandleFunc("/tile", func(w http.ResponseWriter, r *http.Request) {
		// Small 40x40 png
		w.Write([]byte{
			0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x00, 0x00, 0x0d,
			0x49, 0x48, 0x44, 0x52, 0x00, 0x00, 0x00, 0x28, 0x00, 0x00, 0x00, 0x28,
			0x01, 0x03, 0x00, 0x00, 0x00, 0xb6, 0x30, 0x2a, 0x2e, 0x00, 0x00, 0x00,
			0x03, 0x50, 0x4c, 0x54, 0x45, 0x5a, 0xc3, 0x5a, 0xad, 0x38, 0xaa, 0xdb,
			0x00, 0x00, 0x00, 0x0b, 0x49, 0x44, 0x41, 0x54, 0x78, 0x01, 0x63, 0x18,
			0x61, 0x00, 0x00, 0x00, 0xf0, 0x00, 0x01, 0xe2, 0xb8, 0x75, 0x22, 0x00,
			0x00, 0x00, 0x00, 0x49, 0x45, 0x4e, 0x44, 0xae, 0x42, 0x60, 0x82,
		})
	})

	http.HandleFunc("/tiles", func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "<html><body>")
		for i := 0; i < nImgs; i++ {
			fmt.Fprintf(w, `<img src="/tile?cachebust=%d">`, i)
		}
		io.WriteString(w, "</body></html>")
	})
}

var _ = Describe("Chrome tests", func() {
	It("loads a simple hello world page using quic", func(done Done) {
		err := wd.Get("https://quic.clemente.io/hello")
		Expect(err).NotTo(HaveOccurred())
		source, err := wd.PageSource()
		Expect(err).NotTo(HaveOccurred())
		Expect(source).To(ContainSubstring("Hello, World!\n"))
		close(done)
	}, 5)

	It("loads a large number of files", func(done Done) {
		err := wd.Get("https://quic.clemente.io/tiles")
		Expect(err).NotTo(HaveOccurred())
		Eventually(func() error {
			imgs, err := wd.FindElements("tag name", "img")
			if err != nil {
				return err
			}
			if len(imgs) != nImgs {
				return fmt.Errorf("expected number of images to be %d, got %d", nImgs, len(imgs))
			}
			for i, img := range imgs {
				size, err := img.Size()
				if err != nil {
					return err
				}
				if size.Height != imgSize || size.Width != imgSize {
					return fmt.Errorf("image %d did not have expected size", i)
				}
			}
			return nil
		}).ShouldNot(HaveOccurred())
		close(done)
	}, 10)
})
