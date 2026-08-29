package service

import (
	"sync"

	"github.com/LOVECHEN/ntr/core/cred"
	"github.com/LOVECHEN/ntr/core/proxy"
)

// StaticAuth 是配置驱动的静态凭据表:(scheme, key) → cred.Ref。key 的字节形态由协议决定
// (vless=16B UUID / snell=clientID 串),表统一按 string(key) 索引,不解释语义。
//
// 未命中 → (zero,false):协议插件据此决定"响亮拒绝"(vless)还是"落 Ambient"(snell 端口 PSK 已鉴权)。
type StaticAuth struct {
	mu sync.RWMutex
	m  map[authKey]cred.Ref
}

type authKey struct {
	scheme string
	key    string
}

var _ proxy.Authenticator = (*StaticAuth)(nil)

// NewStaticAuth 造空表。
func NewStaticAuth() *StaticAuth { return &StaticAuth{m: make(map[authKey]cred.Ref)} }

// Add 登记一个凭据。热重载时可再调(覆盖同键)。
func (a *StaticAuth) Add(scheme string, key []byte, ref cred.Ref) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.m[authKey{scheme, string(key)}] = ref
}

// Auth 实现 proxy.Authenticator。
func (a *StaticAuth) Auth(scheme string, key []byte) (cred.Ref, bool) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	r, ok := a.m[authKey{scheme, string(key)}]
	return r, ok
}
