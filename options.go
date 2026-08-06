package portscan

import "time"

type config struct {
	concurrency    int
	connectTimeout time.Duration
}

type Scanner struct {
	cfg config
}

func New(opts ...Option) (*Scanner, error) {
	cfg := config{
		concurrency:    100,
		connectTimeout: 500 * time.Millisecond,
	}
	for _, opt := range opts {
		opt(&cfg)
	}
	if cfg.concurrency <= 0 {
		return nil, ErrInvalidConcurrency
	}
	if cfg.connectTimeout <= 0 {
		return nil, ErrInvalidTimeout
	}
	return &Scanner{cfg: cfg}, nil
}

type Option func(*config)

func WithConcurrency(n int) Option {
	return func(c *config) {
		c.concurrency = n
	}
}

func WithConnectTimeout(d time.Duration) Option {
	return func(c *config) {
		c.connectTimeout = d
	}
}
