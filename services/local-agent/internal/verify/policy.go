package verify

import (
	"fmt"
)

type StaticPolicy struct {
	allowedMRTD  map[string]struct{}
	allowedRTMR3 map[string]struct{}
}

func NewStaticPolicy(allowedMRTD []string, allowedRTMR3 []string) StaticPolicy {
	mrtd := make(map[string]struct{}, len(allowedMRTD))
	for _, v := range allowedMRTD {
		mrtd[v] = struct{}{}
	}
	rtmr3 := make(map[string]struct{}, len(allowedRTMR3))
	for _, v := range allowedRTMR3 {
		rtmr3[v] = struct{}{}
	}
	return StaticPolicy{
		allowedMRTD:  mrtd,
		allowedRTMR3: rtmr3,
	}
}

func (p StaticPolicy) CheckMeasurements(bundle Bundle) error {
	if len(p.allowedMRTD) > 0 {
		if _, ok := p.allowedMRTD[bundle.MRTD]; !ok {
			return VerificationError{Code: ReasonMeasurementMismatch, Err: fmt.Errorf("mrtd not allowed")}
		}
	}
	if len(p.allowedRTMR3) > 0 {
		if _, ok := p.allowedRTMR3[bundle.RTMR3]; !ok {
			return VerificationError{Code: ReasonMeasurementMismatch, Err: fmt.Errorf("rtmr3 not allowed")}
		}
	}
	if bundle.RTMR0 == "" || bundle.RTMR1 == "" || bundle.RTMR2 == "" {
		return VerificationError{Code: ReasonMeasurementMismatch, Err: fmt.Errorf("missing runtime measurements")}
	}
	return nil
}
