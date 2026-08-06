package portscan

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestScan(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	openPort := uint16(listener.Addr().(*net.TCPAddr).Port)

	scanner, _ := New(WithConcurrency(2), WithConnectTimeout(100*time.Millisecond))
	ports, _ := List(openPort, 1) // порт 1 обычно закрыт

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	results, err := scanner.Scan(ctx, []string{"127.0.0.1"}, ports)
	if err != nil {
		t.Fatal(err)
	}

	var foundOpen, foundClosed bool
	for res := range results {
		if res.Port == openPort && res.State == StateOpen {
			foundOpen = true
		}
		if res.Port == 1 && res.State == StateClosed {
			foundClosed = true
		}
	}
	if !foundOpen {
		t.Error("open port not detected")
	}
	if !foundClosed {
		t.Error("closed port not detected")
	}
}
