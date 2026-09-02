package config

import (
	"testing"

	"github.com/LOVECHEN/ntr/meter"
)

func TestParseByteSize(t *testing.T) {
	cases := map[string]uint64{
		"1.5gb":   1_500_000_000,
		"512mb":   512_000_000,
		"2gib":    2 << 30,
		"1048576": 1 << 20,
		"1g":      1 << 30,
		"1024":    1024,
		"1kib":    1024,
	}
	for in, want := range cases {
		got, err := parseByteSize(in)
		if err != nil {
			t.Fatalf("parseByteSize(%q): %v", in, err)
		}
		if got != want {
			t.Errorf("parseByteSize(%q)=%d 期望 %d", in, got, want)
		}
	}
	for _, bad := range []string{"", "abc", "-5mb", "mb"} {
		if _, err := parseByteSize(bad); err == nil {
			t.Errorf("parseByteSize(%q) 应报错", bad)
		}
	}
}

func TestParsePercent(t *testing.T) {
	type c struct {
		in  string
		def float64
		exp float64
	}
	for _, tc := range []c{
		{"80%", 0.5, 0.80},
		{"92", 0.5, 0.92},
		{"0.8", 0.5, 0.80},
		{"", 0.75, 0.75},
	} {
		got, err := parsePercent(tc.in, tc.def)
		if err != nil {
			t.Fatalf("parsePercent(%q): %v", tc.in, err)
		}
		if got != tc.exp {
			t.Errorf("parsePercent(%q)=%v 期望 %v", tc.in, got, tc.exp)
		}
	}
	for _, bad := range []string{"0%", "100%", "150%", "-1%", "abc"} {
		if _, err := parsePercent(bad, 0.8); err == nil {
			t.Errorf("parsePercent(%q) 应报错", bad)
		}
	}
}

// TestBuildMemGuard:limit 必填、hard>soft 校验、百分比换算成绝对字节。
func TestBuildMemGuard(t *testing.T) {
	reg := meter.NewRegistry()
	g, err := buildMemGuard(&MemGuardSpec{Limit: "1gb", Soft: "80%", Hard: "90%"}, reg)
	if err != nil {
		t.Fatalf("合法 mem-guard 应能建: %v", err)
	}
	st := g.Stat()
	if st.LimitBytes != 1_000_000_000 {
		t.Errorf("limitBytes=%d", st.LimitBytes)
	}
	if st.SoftBytes != 800_000_000 || st.HardBytes != 900_000_000 {
		t.Errorf("soft/hard 字节换算错: %d/%d", st.SoftBytes, st.HardBytes)
	}

	if _, err := buildMemGuard(&MemGuardSpec{Limit: ""}, reg); err == nil {
		t.Error("limit 空应报错")
	}
	if _, err := buildMemGuard(&MemGuardSpec{Limit: "1gb", Soft: "90%", Hard: "80%"}, reg); err == nil {
		t.Error("hard≤soft 应报错")
	}
	// 缺省 soft/hard = 80%/92%
	g2, err := buildMemGuard(&MemGuardSpec{Limit: "1000"}, reg)
	if err != nil {
		t.Fatal(err)
	}
	if s := g2.Stat(); s.SoftBytes != 800 || s.HardBytes != 920 {
		t.Errorf("缺省 soft/hard 应为 800/920,实为 %d/%d", s.SoftBytes, s.HardBytes)
	}
}
