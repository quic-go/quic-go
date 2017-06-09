package mocks

//go:generate mockgen -destination flow_control_manager.go -package mocks github.com/lucas-clemente/quic-go/flowcontrol FlowControlManager
//go:generate mockgen -destination cpm.go -package mocks github.com/lucas-clemente/quic-go/handshake ConnectionParametersManager
