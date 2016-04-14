package crypto

import (
	"bytes"
	"crypto/rand"
	"io/ioutil"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("AES-GCM AEAD", func() {
	var (
		alice, bob AEAD
	)

	BeforeEach(func() {
		keyAlice := make([]byte, 16)
		keyBob := make([]byte, 16)
		ivAlice := make([]byte, 4)
		ivBob := make([]byte, 4)
		rand.Reader.Read(keyAlice)
		rand.Reader.Read(keyBob)
		rand.Reader.Read(ivAlice)
		rand.Reader.Read(ivBob)
		var err error
		alice, err = NewAEADAESGCM(keyBob, keyAlice, ivBob, ivAlice)
		Expect(err).ToNot(HaveOccurred())
		bob, err = NewAEADAESGCM(keyAlice, keyBob, ivAlice, ivBob)
		Expect(err).ToNot(HaveOccurred())
	})

	It("seals and opens", func() {
		b := &bytes.Buffer{}
		alice.Seal(42, b, []byte("aad"), []byte("foobar"))
		r, err := bob.Open(42, []byte("aad"), b)
		Expect(err).ToNot(HaveOccurred())
		text, err := ioutil.ReadAll(r)
		Expect(err).ToNot(HaveOccurred())
		Expect(text).To(Equal([]byte("foobar")))
	})

	It("seals and opens reverse", func() {
		b := &bytes.Buffer{}
		bob.Seal(42, b, []byte("aad"), []byte("foobar"))
		r, err := alice.Open(42, []byte("aad"), b)
		Expect(err).ToNot(HaveOccurred())
		text, err := ioutil.ReadAll(r)
		Expect(err).ToNot(HaveOccurred())
		Expect(text).To(Equal([]byte("foobar")))
	})

	It("fails with wrong aad", func() {
		b := &bytes.Buffer{}
		alice.Seal(42, b, []byte("aad"), []byte("foobar"))
		_, err := bob.Open(42, []byte("aad2"), b)
		Expect(err).To(MatchError("cipher: message authentication failed"))
	})
})
