package domainsocket

import (
	"context"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
)

func TestSockName(t *testing.T) {
	cases := []struct {
		cfg      Config
		fallback string
		want     string
	}{
		{Config{Path: "/run/a.sock"}, "0.0.0.0:1", "/run/a.sock"},
		{Config{}, "/run/b.sock", "/run/b.sock"},                         // path 缺省回落 listen/server
		{Config{Path: "ntr", Abstract: true}, "", "@ntr"},                // 抽象命名空间加 '@'
		{Config{Path: "@ntr", Abstract: true}, "", "@ntr"},               // 已带 '@' 不重复
		{Config{Path: "ntr", Abstract: true, Padding: true}, "", "@ntr"}, // padding:前缀相同,补零到全长
	}
	for _, c := range cases {
		got, err := (&Transport{cfg: c.cfg}).sockName(c.fallback)
		if err != nil {
			t.Fatal(err)
		}
		if c.cfg.Padding {
			if len(got) != sunPathLen || got[:len(c.want)] != c.want {
				t.Fatalf("padding 名长 %d(期望 %d)前缀 %q", len(got), sunPathLen, got[:len(c.want)])
			}
			continue
		}
		if got != c.want {
			t.Fatalf("%+v → %q,期望 %q", c.cfg, got, c.want)
		}
	}
	if _, err := (&Transport{}).sockName(""); err == nil {
		t.Fatal("无 path 且无回落应报错")
	}
}

// TestRoundTrip:ListenBase / DialBase 经真 unix 套接字往返;残留的旧套接字文件被清掉、关闭后自动删除。
func TestRoundTrip(t *testing.T) {
	dir, err := os.MkdirTemp("", "ntrds")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, "s.sock")
	stale, err := net.Listen("unix", path) // 造一个残留套接字文件
	if err != nil {
		t.Fatal(err)
	}
	stale.(*net.UnixListener).SetUnlinkOnClose(false)
	_ = stale.Close()

	tr := &Transport{cfg: Config{Path: path}}
	ln, err := tr.ListenBase(context.Background(), "")
	if err != nil {
		t.Fatalf("残留套接字未清理:%v", err)
	}
	go func() {
		s, err := ln.Accept()
		if err != nil {
			return
		}
		_, _ = io.Copy(s, s)
		_ = s.Close()
	}()
	c, err := tr.DialBase(context.Background(), "")
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("over-unix-socket")
	if _, err := c.Write(msg); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(msg))
	if _, err := io.ReadFull(c, got); err != nil || string(got) != string(msg) {
		t.Fatalf("回显不符:%q %v", got, err)
	}
	_ = c.Close()
	_ = ln.Close()
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("关闭后套接字文件应删除:%v", err)
	}
}
