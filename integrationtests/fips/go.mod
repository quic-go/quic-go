module github.com/quic-go/quic-go/integrationtests/fips

go 1.26.0

// The version doesn't matter here, as we're replacing it with the currently checked out code anyway.
require github.com/quic-go/quic-go v0.60.0

require github.com/stretchr/testify v1.11.1

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/kr/text v0.2.0 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	golang.org/x/crypto v0.51.0 // indirect
	golang.org/x/net v0.55.0 // indirect
	golang.org/x/sys v0.45.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace github.com/quic-go/quic-go => ../../
