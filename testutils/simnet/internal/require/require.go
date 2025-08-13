package require

import (
    "errors"
    "fmt"
    "reflect"
    "testing"
)

// NoError fails the test if err is not nil.
func NoError(t *testing.T, err error, msgAndArgs ...any) {
	t.Helper()
	if err != nil {
		failNow(t, fmt.Sprintf("expected no error, got: %v", err), msgAndArgs...)
	}
}

// ErrorIs fails the test if err is not target via errors.Is.
func ErrorIs(t *testing.T, err error, target error, msgAndArgs ...any) {
	t.Helper()
	if !errors.Is(err, target) {
		failNow(t, fmt.Sprintf("expected error %v, got: %v", target, err), msgAndArgs...)
	}
}

// Equal fails the test if expected != actual using reflect.DeepEqual.
func Equal(t *testing.T, expected, actual any, msgAndArgs ...any) {
    t.Helper()
    if !reflect.DeepEqual(expected, actual) {
        failNow(t, fmt.Sprintf("not equal\nexpected: %#v\nactual:   %#v", expected, actual), msgAndArgs...)
    }
}

func failNow(t *testing.T, baseMsg string, msgAndArgs ...any) {
    if len(msgAndArgs) > 0 {
        baseMsg = baseMsg + ": " + fmt.Sprint(msgAndArgs...)
    }
    t.Fatalf("%s", baseMsg)
}
