package integrationtests

import (
	"crypto/md5"
	"crypto/rand"
)

type dataManager struct {
	data []byte
	md5  []byte
}

func (m *dataManager) GenerateData(len int) error {
	m.data = make([]byte, len)
	_, err := rand.Read(m.data)
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
