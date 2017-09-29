package mocks

// mockgen source mode doesn't properly recognize structs defined in the same package
// so we have to use sed to correct for that

//go:generate sh -c "mockgen -package mocks_fc -source ../flowcontrol/interface.go | sed \"s/\\[\\]WindowUpdate/[]flowcontrol.WindowUpdate/g\" > mocks_fc/flow_control_manager.go"
//go:generate sh -c "mockgen -package mocks -source ../handshake/params_negotiator_base.go > params_negotiator.go"
//go:generate sh -c "goimports -w ."
