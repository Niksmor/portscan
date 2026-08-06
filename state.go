package portscan

import (
	"context"
	"errors"
	"net"
	"os"
	"syscall"
)

type State uint8

const (
	StateOpen State = iota
	StateClosed
	StateTimeout
	StateUnreachable
	StateCanceled
	StateError
)

func (s State) String() string {
	switch s {
	case StateOpen:
		return "open"
	case StateClosed:
		return "closed"
	case StateTimeout:
		return "timeout"
	case StateUnreachable:
		return "unreachable"
	case StateCanceled:
		return "canceled"
	case StateError:
		return "error"
	default:
		return "unknown"
	}
}

func classifyError(ctx context.Context, err error) State {
	if ctx.Err() != nil {
		return StateCanceled
	}
	if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
		return StateTimeout
	}

	var opErr *net.OpError
	if errors.As(err, &opErr) {
		switch {
		case errors.Is(opErr.Err, syscall.ECONNREFUSED):
			return StateClosed
		case errors.Is(opErr.Err, syscall.ENETUNREACH),
			errors.Is(opErr.Err, syscall.EHOSTUNREACH):
			return StateUnreachable
		}
	}

	var sysErr *os.SyscallError
	if errors.As(err, &sysErr) {
		switch sysErr.Err {
		case syscall.ECONNREFUSED:
			return StateClosed
		case syscall.ENETUNREACH, syscall.EHOSTUNREACH:
			return StateUnreachable
		}
	}

	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return StateUnreachable
	}

	return StateError
}
