package http3

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParsePriority(t *testing.T) {
	// 6 is not a value that any of the test cases sets, so it's easy to spot an unmodified default
	const defaultUrgency int8 = 6

	tests := []struct {
		name            string
		value           string
		wantUrgency     int8
		wantIncremental bool
	}{
		{name: "empty", wantUrgency: defaultUrgency},
		{name: "urgency", value: "u=0", wantUrgency: 0},
		{name: "implicit incremental", value: "i", wantUrgency: defaultUrgency, wantIncremental: true},
		{name: "explicit incremental", value: "i=?1", wantUrgency: defaultUrgency, wantIncremental: true},
		{name: "urgency and non-incremental", value: "i=?0, u=4", wantUrgency: 4},
		{name: "unknown fields", value: "some=data;someparam;u=fake, u=1;foo, i;bar", wantUrgency: 1, wantIncremental: true},
		{name: "repeated fields", value: "u=1,i,u=5,i=?0", wantUrgency: 5},
		{name: "wrong types", value: `u="ignored", i=1`, wantUrgency: defaultUrgency},
		{name: "out of range urgency", value: "u=8", wantUrgency: defaultUrgency},
		{name: "valid unknown SFV types", value: `a=(1 "two" ?1);x, b=:YWJj:, c=%"hello%20world", u=2`, wantUrgency: 2},
		{name: "semicolon inside an extension value", value: `a="x;y";q=1, u=2`, wantUrgency: 2},
		{name: "known fields inside extension values", value: `future="x\",u=0,i", u=5`, wantUrgency: 5},
		{name: "backslash inside a display string", value: `future=%"x\", u=5`, wantUrgency: 5},
		{name: "invalid member", value: "u=0, bad=", wantUrgency: defaultUrgency},
		{name: "unterminated string", value: `u=1,i, invalid="`, wantUrgency: defaultUrgency},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			urgency, incremental := parsePriority(test.value, defaultUrgency, false)
			require.Equal(t, test.wantUrgency, urgency)
			require.Equal(t, test.wantIncremental, incremental)
		})
	}
}

func FuzzParsePriority(f *testing.F) {
	for _, value := range []string{"", "u=0", "i=?0, u=7", `future="x,u=0", u=5`, `u=1, invalid="`} {
		f.Add(value)
	}
	f.Fuzz(func(t *testing.T, value string) {
		urgency, _ := parsePriority(value, defaultPriorityUrgency, false)
		if urgency < 0 || urgency > 7 {
			t.Fatalf("invalid urgency: %d", urgency)
		}
	})
}

func TestServerRequestPriority(t *testing.T) {
	conn := &RawServerConn{}

	urgency, incremental := conn.requestPriority(http.Header{})
	require.Equal(t, defaultPriorityUrgency, urgency)
	require.True(t, incremental)

	header := http.Header{}
	header.Set("Priority", "u=0")
	urgency, incremental = conn.requestPriority(header)
	require.Equal(t, int8(0), urgency)
	require.False(t, incremental)
	require.True(t, conn.priorityAware.Load())

	urgency, incremental = conn.requestPriority(http.Header{})
	require.Equal(t, defaultPriorityUrgency, urgency)
	require.False(t, incremental)

	header.Set("Priority", "i")
	urgency, incremental = conn.requestPriority(header)
	require.Equal(t, defaultPriorityUrgency, urgency)
	require.True(t, incremental)

	conn = &RawServerConn{}
	header.Set("Priority", `u=0, invalid="`)
	urgency, incremental = conn.requestPriority(header)
	require.Equal(t, defaultPriorityUrgency, urgency)
	require.False(t, incremental)
	require.True(t, conn.priorityAware.Load())
}
