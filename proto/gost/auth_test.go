package gost

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/LOVECHEN/ntr/addr"
	"github.com/LOVECHEN/ntr/core/cred"
)

type pipeStream struct{ net.Conn }

func (pipeStream) Unwrap() any { return nil }

type mapAuth map[string]cred.Ref

func (m mapAuth) Auth(scheme string, key []byte) (cred.Ref, bool) {
	r, ok := m[scheme+"|"+string(key)]
	return r, ok
}

// relayPair 真 TCP 上跑 客户端 ClientHandshake(key="user:pass") ↔ 服务端 ServerHandshake,返回归属与服务端错误。
func relayPair(t *testing.T, key []byte, required bool, cfg Config, auth mapAuth) (cred.Ref, error) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	type out struct {
		ref cred.Ref
		err error
	}
	so := make(chan out, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			so <- out{err: err}
			return
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(3 * time.Second))
		p := &Proxy{cfg: cfg}
		p.SetAuthRequired(required)
		_, req, err := p.ServerHandshake(context.Background(), pipeStream{c}, auth)
		if err != nil {
			so <- out{err: err}
			return
		}
		so <- out{ref: req.Cred}
	}()
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	cs, err := (&Proxy{cfg: cfg}).ClientHandshake(context.Background(), pipeStream{c}, key, addr.FromFqdn("t.com", 80))
	if err != nil {
		t.Fatalf("ClientHandshake: %v", err)
	}
	go func() { _, _ = io.Copy(io.Discard, cs) }() // 懒响应:排空,免得服务端写响应阻塞
	o := <-so
	return o.ref, o.err
}

// TestUserPass_TopLevelUsersHit:顶层 users 登记的 "alice:pw" 精确命中 → 归属 alice。
func TestUserPass_TopLevelUsersHit(t *testing.T) {
	alice := cred.Ref{ID: cred.UserBase + 5}
	ref, err := relayPair(t, []byte("alice:pw"), true, Config{}, mapAuth{"gost|alice:pw": alice})
	if err != nil {
		t.Fatalf("应成功: %v", err)
	}
	if ref.ID != alice.ID {
		t.Fatalf("归属应为 alice(%d),实为 %d", alice.ID, ref.ID)
	}
}

// TestUserPass_RequiredReject:配了 users 但凭据未登记且无口级单凭据 → 拒。
func TestUserPass_RequiredReject(t *testing.T) {
	if _, err := relayPair(t, []byte("mallory:x"), true, Config{}, mapAuth{"gost|alice:pw": {ID: cred.UserBase + 5}}); err == nil {
		t.Fatal("未登记凭据应被拒")
	}
}

// TestUserPass_LegacyPortLevel:未配 users、口级 cfg.Username/Password(旧写法)仍生效 → Ambient;不匹配则拒。
func TestUserPass_LegacyPortLevel(t *testing.T) {
	cfg := Config{Username: "u", Password: "p"}
	ref, err := relayPair(t, nil, false, cfg, mapAuth{}) // 客户端 key 空 → 退回 cfg 的 u:p
	if err != nil {
		t.Fatalf("口级凭据匹配应成功: %v", err)
	}
	if ref.ID != cred.Ambient {
		t.Fatalf("口级单凭据归属应为 Ambient,实为 %d", ref.ID)
	}
	if _, err := relayPair(t, []byte("u:wrong"), false, cfg, mapAuth{}); err == nil {
		t.Fatal("口级凭据不匹配应被拒")
	}
}

// TestUserPass_NoAuthWhenNothingConfigured:什么都没配 → 不带凭据也通,Ambient。
func TestUserPass_NoAuthWhenNothingConfigured(t *testing.T) {
	ref, err := relayPair(t, nil, false, Config{}, mapAuth{})
	if err != nil {
		t.Fatalf("no-auth 应通: %v", err)
	}
	if ref.ID != cred.Ambient {
		t.Fatalf("应为 Ambient,实为 %d", ref.ID)
	}
}
