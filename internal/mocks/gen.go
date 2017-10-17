package mocks

//go:generate sh -c "./mockgen_internal.sh mocks flow_control_manager.go github.com/lucas-clemente/quic-go/internal/flowcontrol FlowControlManager"
//go:generate sh -c "goimports -w ."
