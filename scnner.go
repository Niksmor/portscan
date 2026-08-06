package portscan

import (
	"context"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

type job struct {
	host string
	ip   net.IP
	port uint16
}

type target struct {
	Host string
	IP   net.IP
}

func (s *Scanner) Scan(ctx context.Context, hosts []string, ports Ports) (<-chan Result, error) {
	targets, err := resolveTargets(ctx, hosts)
	if err != nil {
		return nil, err
	}
	portList, err := ports.Values()
	if err != nil {
		return nil, err
	}
	if len(portList) == 0 {
		ch := make(chan Result)
		close(ch)
		return ch, nil
	}

	results := make(chan Result, s.cfg.concurrency*2)
	jobs := make(chan job, s.cfg.concurrency*2)

	var wg sync.WaitGroup

	for i := 0; i < s.cfg.concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.worker(ctx, jobs, results)
		}()
	}

	go func() {
		defer close(jobs)
	outer:
		for _, target := range targets {
			for _, port := range portList {
				select {
				case <-ctx.Done():
					break outer
				case jobs <- job{
					host: target.Host,
					ip:   target.IP,
					port: port,
				}:
				}
			}
		}
	}()

	go func() {
		wg.Wait()
		close(results)
	}()

	return results, nil
}

func (s *Scanner) worker(ctx context.Context, jobs <-chan job, results chan<- Result) {
	dialer := net.Dialer{
		Timeout: s.cfg.connectTimeout,
	}

	for j := range jobs {
		start := time.Now()
		state := StateError
		var scanErr error

		address := net.JoinHostPort(j.ip.String(), strconv.Itoa(int(j.port)))
		conn, err := dialer.DialContext(ctx, "tcp", address)
		duration := time.Since(start)

		if err == nil {
			state = StateOpen
			_ = conn.Close()
		} else {
			scanErr = err
			state = classifyError(ctx, err)
		}

		res := Result{
			Host:     j.host,
			IP:       j.ip,
			Port:     j.port,
			State:    state,
			Duration: duration,
			Err:      scanErr,
		}

		select {
		case results <- res:
		case <-ctx.Done():
			res.State = StateCanceled
			select {
			case results <- res:
			default:
			}
			return
		}
	}
}

func resolveTargets(ctx context.Context, hosts []string) ([]target, error) {
	if len(hosts) == 0 {
		return nil, ErrEmptyTargets
	}
	resolver := net.DefaultResolver
	seen := make(map[string]struct{})
	var result []target

	for _, host := range hosts {
		host = strings.TrimSpace(host)
		if host == "" {
			return nil, ErrInvalidHost
		}
		if ip := net.ParseIP(host); ip != nil {
			key := ip.String()
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			result = append(result, target{Host: host, IP: ip})
			continue
		}
		ips, err := resolver.LookupIP(ctx, "ip", host)
		if err != nil {
			return nil, err
		}
		for _, ip := range ips {
			key := ip.String()
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			result = append(result, target{Host: host, IP: ip})
		}
	}
	return result, nil
}
