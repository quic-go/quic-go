package protocol

import "strings"

type CongestionControlAlgorithm uint8

const (
	CUBIC   CongestionControlAlgorithm = 1
	RENO   CongestionControlAlgorithm = 2
)

func GetCongestionType(congestionString string) CongestionControlAlgorithm{
	switch strings.ToLower(congestionString){
	case "cubic":
		return 1
	case "reno":
		return 2
	default:
		return 1
	}
}