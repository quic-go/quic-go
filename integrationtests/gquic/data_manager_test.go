package gquic_test

import (
	"crypto/md5"
	"math/rand"
	"time"

		. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

)

type dataManager struct {
	data []byte
	md5  []byte
}

func (m *dataManager) GenerateData(len int) error {
	m.data = make([]byte, len)
	r := rand.New(rand.NewSource(int64(time.Now().Nanosecond())))
	_, err := r.Read(m.data)
	if err != nil {
		return err
	}
	sum := md5.Sum(m.data)
	m.md5 = sum[:]
	return nil
}

func (m *dataManager) GetData() []byte {
	return m.data
}

func (m *dataManager) GetMD5() []byte {
	return m.md5
}

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
