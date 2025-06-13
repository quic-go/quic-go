package protocol

// [UQUIC]
func GenerateConnectionIDForInitialWithLen(l int) (ConnectionID, error) {
	return GenerateConnectionID(l)
}

type ExpEmptyConnectionIDGenerator struct{}

func (g *ExpEmptyConnectionIDGenerator) GenerateConnectionID() (ConnectionID, error) {
	return GenerateConnectionID(0)
}

func (g *ExpEmptyConnectionIDGenerator) ConnectionIDLen() int {
	return 0
}
