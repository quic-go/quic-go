package integrationtests

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Data Manager", func() {
	dm := dataManager{}

	It("generates data", func() {
		dm.GenerateData(1337)
		data := dm.GetData()
		Expect(data).To(HaveLen(1337))
		Expect(dm.GetMD5()).To(HaveLen(16))
	})

	It("generates random data", func() {
		dm.GenerateData(1337)
		data1 := dm.GetData()
		md51 := dm.GetMD5()
		dm.GenerateData(1337)
		data2 := dm.GetData()
		md52 := dm.GetMD5()
		Expect(data1).ToNot(Equal(data2))
		Expect(md51).ToNot(Equal(md52))
	})
})
