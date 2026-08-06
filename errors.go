package portscan

import "errors"

var (
	ErrEmptyTargets       = errors.New("empty hosts list")
	ErrInvalidHost        = errors.New("invalid host (empty or malformed)")
	ErrEmptyPorts         = errors.New("empty ports list")
	ErrInvalidPort        = errors.New("invalid port (must be 1..65535)")
	ErrInvalidConcurrency = errors.New("concurrency must be positive")
	ErrInvalidTimeout     = errors.New("timeout must be positive")
)
