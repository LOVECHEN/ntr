package snellv45

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"testing"
)

// TestV45RoundTrip:v4/v5 Client ↔ Server 往返(salt + 命令 + 首块 padding + 双向 payload)。
func TestV45RoundTrip(t *testing.T) {
	c, s := net.Pipe()
	defer c.Close()
	defer s.Close()
	psk := []byte("snell-v45-test-psk-0123456789")

	errc := make(chan error, 1)
	go func() {
		cli, err := (&Client{PSK: psk}).DialTCPOver(c, "example.com", 443, nil)
		if err != nil {
			errc <- err
			return
		}
		if _, err := cli.Write([]byte("hello from v45 client")); err != nil {
			errc <- err
			return
		}
		buf := make([]byte, len("ack from v45 server"))
		if _, err := io.ReadFull(cli, buf); err != nil {
			errc <- err
			return
		}
		if string(buf) != "ack from v45 server" {
			errc <- fmt.Errorf("client got %q", buf)
			return
		}
		errc <- nil
	}()

	res, err := (&Server{PSK: psk}).Accept(s)
	if err != nil {
		t.Fatal(err)
	}
	if res.Host != "example.com" || res.Port != 443 {
		t.Fatalf("server decoded dst = %s:%d", res.Host, res.Port)
	}
	if res.Command != CmdConnect {
		t.Fatalf("command = %d", res.Command)
	}
	pl := make([]byte, len("hello from v45 client"))
	if _, err := io.ReadFull(res.Conn, pl); err != nil {
		t.Fatal(err)
	}
	if string(pl) != "hello from v45 client" {
		t.Fatalf("payload = %q", pl)
	}
	if _, err := res.Conn.Write([]byte("ack from v45 server")); err != nil {
		t.Fatal(err)
	}
	if err := <-errc; err != nil {
		t.Fatal(err)
	}
}

// TestV45LargePayload:超过 0x3FFF 的负载会切多帧,往返仍完整。
func TestV45LargePayload(t *testing.T) {
	c, s := net.Pipe()
	defer c.Close()
	defer s.Close()
	psk := []byte("snell-v45-large")
	big := bytes.Repeat([]byte("A"), 100000) // > 0x3FFF,强制多帧

	errc := make(chan error, 1)
	go func() {
		cli, err := (&Client{PSK: psk}).DialTCPOver(c, "h", 1, nil)
		if err != nil {
			errc <- err
			return
		}
		go func() { _, _ = cli.Write(big) }()
		got := make([]byte, len(big))
		_, err = io.ReadFull(cli, got)
		errc <- err
	}()

	res, err := (&Server{PSK: psk}).Accept(s)
	if err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(big))
	if _, err := io.ReadFull(res.Conn, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, big) {
		t.Fatal("server payload mismatch")
	}
	if _, err := res.Conn.Write(big); err != nil {
		t.Fatal(err)
	}
	if err := <-errc; err != nil {
		t.Fatal(err)
	}
}
