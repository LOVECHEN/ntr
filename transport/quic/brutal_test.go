package quic

import (
	"context"
	"testing"
)

// TestBrutalConfig 验通用 Brutal 开关:congestion=brutal 时 Build 把 up/down-mbps 换算成 bps 存进
// brutalUp/brutalDown(客户端发/服务端发);非 brutal 时不启用(0)。
func TestBrutalConfig(t *testing.T) {
	tr, err := Build(context.Background(), Config{Congestion: "brutal", UpMbps: 50, DownMbps: 100}, nil)
	if err != nil {
		t.Fatal(err)
	}
	q := tr.(*Transport)
	if q.brutalUp != 50*125000 {
		t.Errorf("brutalUp=%d 期望 %d(50Mbps→bps)", q.brutalUp, 50*125000)
	}
	if q.brutalDown != 100*125000 {
		t.Errorf("brutalDown=%d 期望 %d(100Mbps→bps)", q.brutalDown, 100*125000)
	}

	// 非 brutal(空 congestion)→ 不启用,退回 quic-go 默认 CC
	tr2, _ := Build(context.Background(), Config{Congestion: "", UpMbps: 50, DownMbps: 100}, nil)
	if q2 := tr2.(*Transport); q2.brutalUp != 0 || q2.brutalDown != 0 {
		t.Errorf("非 brutal 不该启用 Brutal,得 up=%d down=%d", q2.brutalUp, q2.brutalDown)
	}
}
