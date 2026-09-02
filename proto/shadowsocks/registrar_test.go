package shadowsocks

import (
	"context"
	"strings"
	"testing"

	"github.com/LOVECHEN/ntr/core/cred"
	"github.com/LOVECHEN/ntr/core/proxy"
)

// TestRegisterUsers_ClassicMethodRejected:经典 method 无多用户机制,配顶层 users 必须报错(单 principal 豁免,
// 绝不静默把所有人当一个);2022 口缺 password(服务端 iPSK)也必须报错。
func TestRegisterUsers_ClassicMethodRejected(t *testing.T) {
	v, err := Build(context.Background(), Config{Method: "aes-256-gcm", Password: "x"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	err = v.(*Proxy).RegisterUsers([]proxy.RegisteredUser{{Tag: "a@ss", Secret: "k", Ref: cred.Ref{ID: cred.UserBase + 1}}})
	if err == nil || !strings.Contains(err.Error(), "无多用户") {
		t.Fatalf("经典 method 应拒接顶层 users: %v", err)
	}

	v2, err := Build(context.Background(), Config{Method: "2022-blake3-aes-128-gcm", Password: "AAAAAAAAAAAAAAAAAAAAAA=="}, nil)
	if err != nil {
		t.Fatal(err)
	}
	p := v2.(*Proxy)
	p.cfg.Password = "" // 模拟口上没写 iPSK
	err = p.RegisterUsers([]proxy.RegisteredUser{{Tag: "a@ss", Secret: "AAAAAAAAAAAAAAAAAAAAAA==", Ref: cred.Ref{ID: cred.UserBase + 1}}})
	if err == nil || !strings.Contains(err.Error(), "iPSK") {
		t.Fatalf("2022 口缺 password(iPSK)应报错: %v", err)
	}
}

// TestBuild_MultiPSKClientOnly:password 为 iPSK:uPSK(2022 多用户客户端写法)时只建客户端,服务端为 nil
// 且入站握手给出明确错误;单段 password 两端都建。
func TestBuild_MultiPSKClientOnly(t *testing.T) {
	v, err := Build(context.Background(), Config{Method: "2022-blake3-aes-128-gcm", Password: "AAAAAAAAAAAAAAAAAAAAAA==:AQEBAQEBAQEBAQEBAQEBAQ=="}, nil)
	if err != nil {
		t.Fatalf("多段 PSK 客户端应能 Build: %v", err)
	}
	p := v.(*Proxy)
	if p.service != nil || p.method == nil {
		t.Fatal("多段 PSK 应只建客户端 method,服务端 service 为 nil")
	}
	if _, _, err := p.ServerHandshake(context.Background(), nil, nil); err == nil || !strings.Contains(err.Error(), "iPSK:uPSK") {
		t.Fatalf("多段 PSK 口作入站应明确报错: %v", err)
	}
	v2, err := Build(context.Background(), Config{Method: "2022-blake3-aes-128-gcm", Password: "AAAAAAAAAAAAAAAAAAAAAA=="}, nil)
	if err != nil || v2.(*Proxy).service == nil {
		t.Fatalf("单段 PSK 应两端都建: %v", err)
	}
}

// TestRegisterUsers_2022MultiService:2022 口注册两个 uPSK 后 service 换成 MultiService,tag 表齐全。
func TestRegisterUsers_2022MultiService(t *testing.T) {
	v, err := Build(context.Background(), Config{Method: "2022-blake3-aes-128-gcm", Password: "AAAAAAAAAAAAAAAAAAAAAA=="}, nil)
	if err != nil {
		t.Fatal(err)
	}
	p := v.(*Proxy)
	before := p.service
	err = p.RegisterUsers([]proxy.RegisteredUser{
		{Tag: "alice@ss-in", Secret: "AQEBAQEBAQEBAQEBAQEBAQ==", Ref: cred.Ref{ID: cred.UserBase + 1}},
		{Tag: "carol@ss-in", Secret: "AgICAgICAgICAgICAgICAg==", Ref: cred.Ref{ID: cred.UserBase + 2}},
	})
	if err != nil {
		t.Fatalf("2022 注册应成功: %v", err)
	}
	if p.service == before {
		t.Fatal("service 应换成 MultiService")
	}
	if len(p.users.m) != 2 || p.users.m["carol@ss-in"].ID != cred.UserBase+2 {
		t.Fatalf("tag 表错: %+v", p.users.m)
	}
}
