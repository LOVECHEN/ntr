package main

// ech-keygen 子命令:生成一对 ECH 密钥,与 sing-box `generate ech-keypair` 逐字节兼容。
//   ntr ech-keygen [public-name]   # 默认 public-name = public.example
// 输出 ECH CONFIGS(给客户端 tls.ech-config)+ ECH KEYS(给服务端 tls.ech-key)。

import (
	"fmt"
	"os"

	"github.com/LOVECHEN/ntr/transport/tls"
)

func runECHKeygen(args []string) {
	publicName := "public.example"
	if len(args) > 0 && args[0] != "" {
		publicName = args[0]
	}
	configPem, keyPem, err := tls.ECHKeygen(publicName)
	if err != nil {
		fmt.Fprintln(os.Stderr, "ech-keygen:", err)
		os.Exit(1)
	}
	fmt.Print(configPem)
	fmt.Print(keyPem)
}
