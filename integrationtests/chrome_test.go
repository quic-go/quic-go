package integrationtests

import (
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"strconv"

	"github.com/tebeka/selenium"

	"github.com/lucas-clemente/quic-go/protocol"
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
	It("does not work with mismatching versions", func() {
		versionForUs := protocol.SupportedVersions[0]
		versionForChrome := protocol.SupportedVersions[len(protocol.SupportedVersions)-1]

		// If both are equal, this test doesn't make any sense.
		if versionForChrome == versionForUs {
			return
		}

		supportedVersionsBefore := protocol.SupportedVersions
		protocol.SupportedVersions = []protocol.VersionNumber{versionForUs}
		wd := getWebdriverForVersion(versionForChrome)

		defer func() {
			protocol.SupportedVersions = supportedVersionsBefore
			wd.Close()
		}()

		err := wd.Get("https://quic.clemente.io/hello")
		Expect(err).NotTo(HaveOccurred())
		source, err := wd.PageSource()
		Expect(err).NotTo(HaveOccurred())
		Expect(source).ToNot(ContainSubstring("Hello, World!\n"))
	})

	for i := range protocol.SupportedVersions {
		version := protocol.SupportedVersions[i]

		Context(fmt.Sprintf("with quic version %d", version), func() {
			var (
				wd                      selenium.WebDriver
				supportedVersionsBefore []protocol.VersionNumber
			)

			BeforeEach(func() {
				supportedVersionsBefore = protocol.SupportedVersions
				protocol.SupportedVersions = []protocol.VersionNumber{version}
				wd = getWebdriverForVersion(version)
			})

			AfterEach(func() {
				wd.Close()
				protocol.SupportedVersions = supportedVersionsBefore
			})

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
				}, 5).ShouldNot(HaveOccurred())
				close(done)
			}, 10)

			It("downloads a small file", func() {
				dataMan.GenerateData(dataLen)
				err := wd.Get("https://quic.clemente.io/data")
				Expect(err).NotTo(HaveOccurred())
				Eventually(func() int { return getDownloadSize("data") }, 30, 0.1).Should(Equal(dataLen))
				Expect(getDownloadMD5("data")).To(Equal(dataMan.GetMD5()))
			}, 60)

			It("downloads a large file", func() {
				dataMan.GenerateData(dataLongLen)
				err := wd.Get("https://quic.clemente.io/data")
				Expect(err).NotTo(HaveOccurred())
				Eventually(func() int { return getDownloadSize("data") }, 90, 0.5).Should(Equal(dataLongLen))
				Expect(getDownloadMD5("data")).To(Equal(dataMan.GetMD5()))
			}, 100)

			It("uploads a small file", func() {
				dataMan.GenerateData(dataLen)
				data := dataMan.GetData()
				dir, err := ioutil.TempDir("", "quic-upload-src")
				Expect(err).ToNot(HaveOccurred())
				defer os.RemoveAll(dir)
				tmpfn := filepath.Join(dir, "data.dat")
				err = ioutil.WriteFile(tmpfn, data, 0777)
				Expect(err).ToNot(HaveOccurred())
				copyFileToDocker(tmpfn)

				err = wd.Get("https://quic.clemente.io/uploadform?num=1")
				Expect(err).NotTo(HaveOccurred())
				elem, err := wd.FindElement(selenium.ByCSSSelector, "#upload_0")
				Expect(err).ToNot(HaveOccurred())
				err = elem.SendKeys("/home/seluser/data.dat")
				Expect(err).ToNot(HaveOccurred())
				Eventually(func() error { return elem.Submit() }, 30, 0.1).ShouldNot(HaveOccurred())

				file := filepath.Join(uploadDir, "data.dat")
				Expect(getFileSize(file)).To(Equal(dataLen))
				Expect(getFileMD5(file)).To(Equal(dataMan.GetMD5()))
			})

			It("uploads a large file", func() {
				dataMan.GenerateData(dataLongLen)
				data := dataMan.GetData()
				dir, err := ioutil.TempDir("", "quic-upload-src")
				Expect(err).ToNot(HaveOccurred())
				defer os.RemoveAll(dir)
				tmpfn := filepath.Join(dir, "data.dat")
				err = ioutil.WriteFile(tmpfn, data, 0777)
				Expect(err).ToNot(HaveOccurred())
				copyFileToDocker(tmpfn)

				err = wd.Get("https://quic.clemente.io/uploadform?num=1")
				Expect(err).NotTo(HaveOccurred())
				elem, err := wd.FindElement(selenium.ByCSSSelector, "#upload_0")
				Expect(err).ToNot(HaveOccurred())
				err = elem.SendKeys("/home/seluser/data.dat")
				Expect(err).ToNot(HaveOccurred())
				Eventually(func() error { return elem.Submit() }, 90, 0.5).ShouldNot(HaveOccurred())

				file := filepath.Join(uploadDir, "data.dat")
				Expect(getFileSize(file)).To(Equal(dataLongLen))
				Expect(getFileMD5(file)).To(Equal(dataMan.GetMD5()))
			})

			// this test takes a long time because it copies every file into the docker container one by one
			// unfortunately, docker doesn't support copying multiple files at once
			// see https://github.com/docker/docker/issues/7710
			It("uploads many small files", func() {
				num := protocol.MaxStreamsPerConnection + 20

				dir, err := ioutil.TempDir("", "quic-upload-src")
				Expect(err).ToNot(HaveOccurred())
				defer os.RemoveAll(dir)

				var md5s [][]byte

				for i := 0; i < num; i++ {
					dataMan.GenerateData(dataLen)
					data := dataMan.GetData()
					md5s = append(md5s, dataMan.GetMD5())
					tmpfn := filepath.Join(dir, "data_"+strconv.Itoa(i)+".dat")
					err = ioutil.WriteFile(tmpfn, data, 0777)
					Expect(err).ToNot(HaveOccurred())
					copyFileToDocker(tmpfn)
				}

				err = wd.Get("https://quic.clemente.io/uploadform?num=" + strconv.Itoa(num))
				Expect(err).NotTo(HaveOccurred())

				for i := 0; i < num; i++ {
					var elem selenium.WebElement
					elem, err = wd.FindElement(selenium.ByCSSSelector, "#upload_"+strconv.Itoa(i))
					Expect(err).ToNot(HaveOccurred())
					err = elem.SendKeys("/home/seluser/data_" + strconv.Itoa(i) + ".dat")
					Expect(err).ToNot(HaveOccurred())
				}

				elem, err := wd.FindElement(selenium.ByCSSSelector, "#form")
				Expect(err).ToNot(HaveOccurred())
				Eventually(func() error { return elem.Submit() }, 30, 0.1).ShouldNot(HaveOccurred())

				for i := 0; i < num; i++ {
					file := filepath.Join(uploadDir, "data_"+strconv.Itoa(i)+".dat")
					Expect(getFileSize(file)).To(Equal(dataLen))
					Expect(getFileMD5(file)).To(Equal(md5s[i]))
				}
			})
		})
	}
})
