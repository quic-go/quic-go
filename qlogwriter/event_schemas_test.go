package qlogwriter

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// resetEventSchemas clears the registered event schemas for the duration of the test.
func resetEventSchemas(t *testing.T) {
	t.Helper()

	orig := registeredEventSchemas
	registeredEventSchemas = nil
	t.Cleanup(func() { registeredEventSchemas = orig })
}

func TestRegisterEventSchema(t *testing.T) {
	resetEventSchemas(t)

	RegisterEventSchema("urn:ietf:params:qlog:events:foo")
	RegisterEventSchema("urn:ietf:params:qlog:events:bar")
	RegisterEventSchema("urn:ietf:params:qlog:events:foo")
	RegisterEventSchema("urn:ietf:params:qlog:events:baz")
	require.Equal(t,
		[]string{"urn:ietf:params:qlog:events:foo", "urn:ietf:params:qlog:events:bar", "urn:ietf:params:qlog:events:baz"},
		registeredEventSchemas,
	)
}
