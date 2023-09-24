package qlog

import (
	"encoding/json"
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestQlog(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "qlog Suite")
}

func checkEncoding(data []byte, expected map[string]interface{}) {
	// unmarshal the data
	m := make(map[string]interface{})
	ExpectWithOffset(2, json.Unmarshal(data, &m)).To(Succeed())
	ExpectWithOffset(2, m).To(HaveLen(len(expected)))
	for key, value := range expected {
		switch v := value.(type) {
		case bool, string, map[string]interface{}:
			ExpectWithOffset(1, m).To(HaveKeyWithValue(key, v))
		case int:
			ExpectWithOffset(1, m).To(HaveKeyWithValue(key, float64(v)))
		case [][]float64: // used in the ACK frame
			ExpectWithOffset(1, m).To(HaveKey(key))
			for i, l := range v {
				for j, s := range l {
					ExpectWithOffset(1, m[key].([]interface{})[i].([]interface{})[j].(float64)).To(Equal(s))
				}
			}
		default:
			Fail("unexpected type")
		}
	}
}
