package handshake

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

type target struct {
	Name    string
	Version string

	callback func(label string, length int) error
}

type renamedField struct {
	NewName string
	Version string

	callback func(label string, length int) error
}

type renamedPrivateField struct {
	Name    string
	Version string

	cb func(label string, length int) error
}

type additionalField struct {
	Name    string
	Version string

	callback func(label string, length int) error
	secret   []byte
}

type interchangedFields struct {
	Version string
	Name    string

	callback func(label string, length int) error
}

type renamedCallbackFunctionParams struct { // should be equivalent
	Name    string
	Version string

	callback func(newLabel string, length int) error
}

var _ = Describe("Unsafe checks", func() {
	It("detects if an unsafe conversion is safe", func() {
		Expect(structsEqual(&target{}, &target{})).To(BeTrue())
		Expect(structsEqual(&target{}, &renamedField{})).To(BeFalse())
		Expect(structsEqual(&target{}, &renamedPrivateField{})).To(BeFalse())
		Expect(structsEqual(&target{}, &additionalField{})).To(BeFalse())
		Expect(structsEqual(&target{}, &interchangedFields{})).To(BeFalse())
		Expect(structsEqual(&target{}, &renamedCallbackFunctionParams{})).To(BeTrue())
	})
})
