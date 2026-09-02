package endpoint

import (
	"testing"

	"github.com/LOVECHEN/ntr/core/cred"
)

func TestCredBindPreAuthThenPromote(t *testing.T) {
	m := &Metadata{}
	m.BindCred(cred.Ref{ID: cred.Unmatched})    // pre-auth 期
	m.BindCred(cred.Ref{ID: cred.UserBase + 5}) // 鉴权完成追认一次 —— 允许
	if m.CredID() != cred.UserBase+5 {
		t.Fatalf("promoted cred = %d, want %d", m.CredID(), cred.UserBase+5)
	}
}

func TestCredReBindAfterAuthPanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("expected panic on re-bind to a different real cred after auth")
		}
	}()
	m := &Metadata{}
	m.BindCred(cred.Ref{ID: cred.UserBase + 1})
	m.BindCred(cred.Ref{ID: cred.UserBase + 2}) // 冻结后再改 → panic
}

func TestSniffDoubleWritePanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("expected panic on sniff double-write")
		}
	}()
	m := &Metadata{}
	m.SetSniff(SniffTLS, "example.com", SniffFailNone)
	m.SetSniff(SniffHTTP, "other.com", SniffFailNone)
}

func TestSniffDomainGetter(t *testing.T) {
	m := &Metadata{}
	if _, ok := m.SniffDomain(); ok {
		t.Fatal("empty metadata should report no sniff domain")
	}
	m.SetSniff(SniffTLS, "sni.example", SniffFailNone)
	d, ok := m.SniffDomain()
	if !ok || d != "sni.example" {
		t.Fatalf("SniffDomain = %q,%v", d, ok)
	}
}
