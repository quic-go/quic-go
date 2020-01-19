package qlog

import (
	"encoding/json"
	"testing"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

func TestQlog(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "qlog Suite")
}

func checkEncoding(data []byte, expected map[string](interface{})) {
	// unmarshal the data
	m := make(map[string](interface{}))
	ExpectWithOffset(1, json.Unmarshal(data, &m)).To(Succeed())
	ExpectWithOffset(1, m).To(HaveLen(len(expected)))
	for key, value := range expected {
		switch value.(type) {
		case string:
			ExpectWithOffset(1, m).To(HaveKeyWithValue(key, value))
		case int:
			ExpectWithOffset(1, m).To(HaveKeyWithValue(key, float64(value.(int))))
		case bool:
			ExpectWithOffset(1, m).To(HaveKeyWithValue(key, value.(bool)))
		case [][]string: // used in the ACK frame
			ExpectWithOffset(1, m).To(HaveKey(key))
			for i, l := range value.([][]string) {
				for j, s := range l {
					ExpectWithOffset(1, m[key].([]interface{})[i].([]interface{})[j].(string)).To(Equal(s))
				}
			}
		default:
			Fail("unexpected type")
		}
	}
}
