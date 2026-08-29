package vless

import "testing"

// TestFlowAddonRoundTrip:flow addon 编解码往返 + 空/非法输入不 panic。
func TestFlowAddonRoundTrip(t *testing.T) {
	enc := encodeFlowAddon(flowVision)
	if got := parseFlowAddon(enc); got != flowVision {
		t.Fatalf("往返 = %q, want %q", got, flowVision)
	}
	// addon 结构:0x0A <16> "xtls-rprx-vision" = 18 字节
	if len(enc) != 18 || enc[0] != 0x0A || enc[1] != 16 {
		t.Fatalf("addon 结构错:%x", enc)
	}
	if parseFlowAddon(nil) != "" || parseFlowAddon([]byte{0x0A}) != "" || parseFlowAddon([]byte{0x08, 0x01}) != "" {
		t.Fatal("空/截断/非 flow addon 应返回空,不 panic")
	}
}
