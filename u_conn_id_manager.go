package quic

// [UQUIC]
func (h *connIDManager) SetConnectionIDLimit(limit uint64) {
	h.connectionIDLimit = limit
}
