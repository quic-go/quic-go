package main

import "github.com/danielpfeifer02/quic-go-prio-packs/http3"

// The contents of this script don't matter.
// We just need to make sure that quic-go is imported.
func main() {
	_ = http3.Server{}
}
