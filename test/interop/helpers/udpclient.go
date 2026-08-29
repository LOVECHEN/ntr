//go:build ignore

// 极简 UDP 客户端:向 host:port 发一包,等回显,一致则打印 UDP-CLIENT-OK。
// 用法:udpclient <host:port> <msg>
package main

import (
	"fmt"
	"net"
	"os"
	"time"
)

func main() {
	if len(os.Args) != 3 {
		fmt.Println("usage: udpclient host:port msg")
		os.Exit(2)
	}
	c, err := net.DialTimeout("udp", os.Args[1], 5*time.Second)
	if err != nil {
		fmt.Println("dial:", err)
		os.Exit(1)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(6 * time.Second))
	msg := []byte(os.Args[2])
	if _, err := c.Write(msg); err != nil {
		fmt.Println("write:", err)
		os.Exit(1)
	}
	b := make([]byte, 2048)
	n, err := c.Read(b)
	if err != nil {
		fmt.Println("read:", err)
		os.Exit(1)
	}
	if string(b[:n]) != string(msg) {
		fmt.Printf("MISMATCH %q != %q\n", b[:n], msg)
		os.Exit(1)
	}
	fmt.Println("UDP-CLIENT-OK")
}
