package mocks

//go:generate mockgen -destination mocks_fc/flow_control_manager.go -package mocks_fc github.com/lucas-clemente/quic-go/internal/flowcontrol FlowControlManager
//go:generate mockgen -destination cpm.go -package mocks github.com/lucas-clemente/quic-go/handshake ConnectionParametersManager
