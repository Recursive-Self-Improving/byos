package auththrottle

import (
	"errors"
	"time"
)

const (
	SurfaceWebPassword Surface = "web_password"
	SurfaceAdminBearer Surface = "admin_bearer"
)

type Surface string

type Policy struct {
	FailureResetAfter     time.Duration
	CooldownAfterThree    time.Duration
	CooldownAfterFour     time.Duration
	LockAfterFive         time.Duration
	GlobalWindow          time.Duration
	GlobalSourceLockLimit int
	GlobalBlockDuration   time.Duration
	SourceRetention       time.Duration
}

func DefaultPolicy() Policy {
	return Policy{
		FailureResetAfter:     15 * time.Minute,
		CooldownAfterThree:    5 * time.Second,
		CooldownAfterFour:     30 * time.Second,
		LockAfterFive:         15 * time.Minute,
		GlobalWindow:          15 * time.Minute,
		GlobalSourceLockLimit: 25,
		GlobalBlockDuration:   time.Minute,
		SourceRetention:       24 * time.Hour,
	}
}

func (p Policy) Validate() error {
	if p.FailureResetAfter <= 0 || p.CooldownAfterThree <= 0 || p.CooldownAfterFour <= 0 || p.LockAfterFive <= 0 || p.GlobalWindow <= 0 || p.GlobalBlockDuration <= 0 || p.SourceRetention <= 0 {
		return errors.New("authentication throttle durations must be positive")
	}
	if p.GlobalSourceLockLimit < 2 {
		return errors.New("authentication throttle global threshold must be at least two")
	}
	return nil
}
