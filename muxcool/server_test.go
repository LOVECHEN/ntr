package muxcool

import (
	"errors"
	"net"
	"testing"
	"time"
)

type mockDisp struct {
	conn    net.Conn
	gotNet  TargetNetwork
	gotAddr Address
	gotPort uint16
}

func (d *mockDisp) DialTarget(n TargetNetwork, a Address, p uint16) (net.Conn, error) {
	d.gotNet, d.gotAddr, d.gotPort = n, a, p
	return d.conn, nil
}

func readFrameT(t *testing.T, c net.Conn) (*FrameMetadata, []byte) {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
	m, d, err := ReadFrame(c)
	if err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}
	return m, d
}

// Portal 开一个 TCP 子流,数据落地到本地目标,响应回程为 Keep,关闭为 End。
func TestServerWorker_NewTCP_Bidirectional(t *testing.T) {
	portal, bridge := net.Pipe() // mux 链路
	service, dial := net.Pipe()  // 本地目标(service=测试持有,dial=worker 落地端)
	disp := &mockDisp{conn: dial}

	w := NewServerWorker(bridge, disp, nil)
	go w.Run()
	defer bridge.Close()

	// service 端:收到 "ping" 就回 "pong",然后关闭。
	go func() {
		buf := make([]byte, 64)
		_ = service.SetReadDeadline(time.Now().Add(3 * time.Second))
		n, err := service.Read(buf)
		if err == nil && string(buf[:n]) == "ping" {
			service.Write([]byte("pong"))
		}
		time.Sleep(50 * time.Millisecond)
		service.Close()
	}()

	// Portal 发 New(SID=1, TCP, 1.2.3.4:80, "ping")。
	m := &FrameMetadata{SessionID: 1, Status: StatusNew, Network: NetworkTCP,
		Address: Address{IP: net.IPv4(1, 2, 3, 4)}, Port: 80}
	_ = portal.SetWriteDeadline(time.Now().Add(3 * time.Second))
	if err := WriteFrame(portal, m, []byte("ping")); err != nil {
		t.Fatal(err)
	}

	// 期望:Keep(SID=1, "pong")。
	rm, rd := readFrameT(t, portal)
	if rm.SessionID != 1 || rm.Status != StatusKeep || string(rd) != "pong" {
		t.Fatalf("unexpected response: sid=%d status=%v data=%q", rm.SessionID, rm.Status, rd)
	}

	// 期望:End(SID=1)。
	em, _ := readFrameT(t, portal)
	if em.SessionID != 1 || em.Status != StatusEnd {
		t.Fatalf("expected End(1), got sid=%d status=%v", em.SessionID, em.Status)
	}

	// dispatcher 收到的 target 正确。
	if disp.gotNet != NetworkTCP || disp.gotPort != 80 || !disp.gotAddr.IP.Equal(net.IPv4(1, 2, 3, 4)) {
		t.Fatalf("dispatcher got wrong target: %v %v :%d", disp.gotNet, disp.gotAddr, disp.gotPort)
	}
}

// 控制子流(target 域 "reverse"):数据经 onControl 回调,不落地。
func TestServerWorker_ControlSubstream(t *testing.T) {
	portal, bridge := net.Pipe()
	got := make(chan []byte, 4)
	disp := &mockDisp{} // 控制流不该触发 dial
	w := NewServerWorker(bridge, disp, func(p []byte) {
		cp := make([]byte, len(p))
		copy(cp, p)
		got <- cp
	})
	go w.Run()
	defer bridge.Close()

	_ = portal.SetWriteDeadline(time.Now().Add(3 * time.Second))
	// New(SID=2, UDP, "reverse":0)
	newCtl := &FrameMetadata{SessionID: 2, Status: StatusNew, Network: NetworkUDP,
		Address: Address{IsDomain: true, Domain: InternalDomain}, Port: 0}
	if err := WriteFrame(portal, newCtl, nil); err != nil {
		t.Fatal(err)
	}
	// 一条 DRAIN 心跳字节:08 01 9A 06 <len=2> AA BB
	ctl := []byte{0x08, 0x01, 0x9A, 0x06, 0x02, 0xAA, 0xBB}
	if err := WriteData(portal, 2, ctl); err != nil {
		t.Fatal(err)
	}

	select {
	case p := <-got:
		if string(p) != string(ctl) {
			t.Fatalf("control payload mismatch: %x", p)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("onControl not called")
	}
	if disp.conn != nil {
		t.Fatal("control substream must not dial")
	}
}

// blockingDisp —— DialTarget 阻塞直到 release 关闭(模拟拨号慢 / 黑洞目标)。
type blockingDisp struct{ release chan struct{} }

func (d *blockingDisp) DialTarget(TargetNetwork, Address, uint16) (net.Conn, error) {
	<-d.release
	return nil, errors.New("blockingDisp released")
}

// ★核心修复验证:DialTarget 慢/黑洞不应冻结读环。异步 land 后,一个拨不通的 New 在 goroutine
// 里挂着,读环仍能及时处理后续的控制心跳。若 DialTarget 还在读环内(旧逻辑),此测试超时失败。
func TestServerWorker_SlowDialDoesNotBlockReadLoop(t *testing.T) {
	portal, bridge := net.Pipe()
	release := make(chan struct{})
	defer close(release)
	got := make(chan []byte, 1)
	w := NewServerWorker(bridge, &blockingDisp{release: release}, func(p []byte) {
		got <- append([]byte(nil), p...)
	})
	go w.Run()
	defer bridge.Close()

	_ = portal.SetWriteDeadline(time.Now().Add(3 * time.Second))
	// New(1, TCP, 黑洞目标):DialTarget 会阻塞(在 land goroutine 里)。
	nm := &FrameMetadata{SessionID: 1, Status: StatusNew, Network: NetworkTCP,
		Address: Address{IP: net.IPv4(10, 0, 0, 1)}, Port: 80}
	if err := WriteFrame(portal, nm, nil); err != nil {
		t.Fatal(err)
	}
	// 紧接着:控制子流 + 一条心跳。读环若被上一个拨号卡住,这里永远收不到。
	ctlNew := &FrameMetadata{SessionID: 2, Status: StatusNew, Network: NetworkUDP,
		Address: Address{IsDomain: true, Domain: InternalDomain}, Port: 0}
	if err := WriteFrame(portal, ctlNew, nil); err != nil {
		t.Fatal(err)
	}
	if err := WriteData(portal, 2, []byte{0x9A, 0x06, 0x01, 0xAB}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-got: // ✅ 读环未被黑洞拨号冻结
	case <-time.After(2 * time.Second):
		t.Fatal("读环被慢速 DialTarget 阻塞:控制心跳未处理(异步 land 修复失效)")
	}
}

// ★关停可中断验证:HoL 背压下 Run 卡在 bufPipe.Write 时,Close() 应能打断使 Run 返回
// (否则 ctx 取消 / Bridge 关停会 hang)。
func TestServerWorker_CloseUnblocksStuckWrite(t *testing.T) {
	portal, bridge := net.Pipe()
	_, dial := net.Pipe() // service 端不读 → 落地 conn 写阻塞 → 上行 io.Copy 停 → bufPipe 填满
	w := NewServerWorker(bridge, &mockDisp{conn: dial}, nil)
	runDone := make(chan error, 1)
	go func() { runDone <- w.Run() }()
	defer bridge.Close()

	go func() {
		_ = portal.SetWriteDeadline(time.Now().Add(3 * time.Second))
		nm := &FrameMetadata{SessionID: 1, Status: StatusNew, Network: NetworkTCP,
			Address: Address{IP: net.IPv4(1, 2, 3, 4)}, Port: 80}
		WriteFrame(portal, nm, nil)
		big := make([]byte, 8192)
		for i := 0; i < 20; i++ { // 160KiB > 64KiB bufPipe → 读环卡在 inW.Write
			if WriteData(portal, 1, big) != nil {
				return
			}
		}
	}()
	time.Sleep(300 * time.Millisecond) // 让读环卡进 bufPipe.Write
	_ = w.Close()                      // 应关 inW(唤醒卡住的 Write)+ 关 link → Run 退出
	select {
	case <-runDone: // ✅ 关停未 hang
	case <-time.After(2 * time.Second):
		t.Fatal("Close 未能打断卡在 bufPipe.Write 的读环(关停会 hang)")
	}
}

// ★同 id 保护验证:Portal 在活跃 id 上再发 New 应被拒(回 End+error),不覆盖旧会话(防泄漏 + 误删)。
func TestServerWorker_DuplicateID_Rejected(t *testing.T) {
	portal, bridge := net.Pipe()
	_, dial := net.Pipe()
	w := NewServerWorker(bridge, &mockDisp{conn: dial}, nil)
	go w.Run()
	defer bridge.Close()

	_ = portal.SetWriteDeadline(time.Now().Add(3 * time.Second))
	nm := &FrameMetadata{SessionID: 1, Status: StatusNew, Network: NetworkTCP,
		Address: Address{IP: net.IPv4(1, 2, 3, 4)}, Port: 80}
	if err := WriteFrame(portal, nm, nil); err != nil { // 第一条:建会话(land 异步,下行不发帧)
		t.Fatal(err)
	}
	if err := WriteFrame(portal, nm, nil); err != nil { // 同 id 第二条:应被拒
		t.Fatal(err)
	}
	em, _ := readFrameT(t, portal)
	if em.SessionID != 1 || em.Status != StatusEnd || !em.Option.Has(OptionError) {
		t.Fatalf("重复 id 应回 End+error,得 sid=%d status=%v opt=%v", em.SessionID, em.Status, em.Option)
	}
}

// Keep 到未知会话 → Bridge 回一个 End 通知对端关闭。
func TestServerWorker_KeepUnknown_RepliesEnd(t *testing.T) {
	portal, bridge := net.Pipe()
	w := NewServerWorker(bridge, &mockDisp{}, nil)
	go w.Run()
	defer bridge.Close()

	_ = portal.SetWriteDeadline(time.Now().Add(3 * time.Second))
	if err := WriteData(portal, 99, []byte("orphan")); err != nil {
		t.Fatal(err)
	}
	em, _ := readFrameT(t, portal)
	if em.SessionID != 99 || em.Status != StatusEnd {
		t.Fatalf("expected End(99), got sid=%d status=%v", em.SessionID, em.Status)
	}
}
