//go:build ignore

// 极简 UDP echo:监听 :5353,原样回发。
package main

import "net"

func main() {
	pc, err := net.ListenPacket("udp", ":5353")
	if err != nil {
		panic(err)
	}
	b := make([]byte, 65535)
	for {
		n, a, err := pc.ReadFrom(b)
		if err != nil {
			continue
		}
		pc.WriteTo(b[:n], a)
	}
}
