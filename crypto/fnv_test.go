package crypto

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("FNV", func() {
	It("gives proper null hash", func() {
		hash := New128a()
		h, l := hash.Sum128()
		Expect(l).To(Equal(uint64(0x62b821756295c58d)))
		Expect(h).To(Equal(uint64(0x6c62272e07bb0142)))
	})

	It("calculates hash", func() {
		hash := New128a()
		_, err := hash.Write([]byte("foobar"))
		Expect(err).ToNot(HaveOccurred())
		h, l := hash.Sum128()
		Expect(l).To(Equal(uint64(0x6f0d3597ba446f18)))
		Expect(h).To(Equal(uint64(0x343e1662793c64bf)))
	})
})
