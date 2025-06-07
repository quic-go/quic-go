package qerr

// Multipath error codes
const (
	// APPLICATION_ABANDON indicates that the path was abandoned by the application.
	// This is a placeholder value using the experimental range.
	APPLICATION_ABANDON TransportErrorCode = 0xMA00
	// RESOURCE_LIMIT_REACHED indicates that a resource limit was reached, leading to path abandonment.
	// This is a placeholder value using the experimental range.
	RESOURCE_LIMIT_REACHED TransportErrorCode = 0xMA01
	// UNSTABLE_INTERFACE indicates that the underlying network interface for the path became unstable.
	// This is a placeholder value using the experimental range.
	UNSTABLE_INTERFACE TransportErrorCode = 0xMA02
	// NO_CID_AVAILABLE indicates that no connection ID was available to continue using the path.
	// This is a placeholder value using the experimental range.
	NO_CID_AVAILABLE TransportErrorCode = 0xMA03
)
[end of internal/qerr/multipath_error_codes.go]
