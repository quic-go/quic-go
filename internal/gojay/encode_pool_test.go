package gojay

import (
	"fmt"
	"log"
	"strconv"
	"testing"
	"time"
)

func TestConcurrencyMarshal(t *testing.T) {
	var f = func(num int, t *testing.T) {
		for {
			b, err := Marshal(num)
			if err != nil {
				log.Fatal(err)
			}

			s := string(b)
			if n, err := strconv.Atoi(s); err != nil || n != num {
				t.Error(fmt.Errorf(
					"caught race: %v %v", s, num,
				))
			}
		}
	}

	for i := 0; i < 100; i++ {
		go f(i, t)
	}
	time.Sleep(2 * time.Second)
}
