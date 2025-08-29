package monotime

import (
	"time"
)

var start = time.Now()

type Time int64

func Now() Time {
	return Time(time.Since(start).Nanoseconds())
}

func (t Time) Sub(t2 Time) time.Duration {
	return time.Duration(t - t2)
}

func (t Time) Add(d time.Duration) Time {
	return Time(int64(t) + d.Nanoseconds())
}

func (t Time) After(t2 Time) bool {
	return t > t2
}

func (t Time) Before(t2 Time) bool {
	return t < t2
}

func (t Time) IsZero() bool {
	return t == 0
}

func (t Time) Equal(t2 Time) bool {
	return t == t2
}

func Until(t Time) time.Duration {
	return time.Duration(t - Now())
}
