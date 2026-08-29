package protocol

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"net"

	sscore "github.com/LOVECHEN/ntr/internal/ssr/sscore"
	"github.com/LOVECHEN/ntr/internal/ssr/tools"
)

// PickServerProtocol 建服务端 protocol 逆向包装。支持 origin(透传,由调用方处理)+
// auth_aes128_sha1 / auth_aes128_md5 / auth_sha1_v4 / auth_chain_a / auth_chain_b(全 6 种)。
//
// 服务端语义(与客户端镜像,禁改线格式):
//   - Encode(回程 server→client):强制走 packData(置 hasSentHeader=true,不发 auth 头);
//     packData 逻辑与客户端逐字节相同,故客户端 Decode 直接吃。
//   - Decode(入站 client→server):首包先解 packAuthData 头(parseAuthHead,packAuthData 的逆),
//     抽出内嵌首段数据,之后复用客户端 Decode 的 chunk loop。
func PickServerProtocol(name string, c net.Conn, iv, key []byte, overhead int, param string) (net.Conn, error) {
	b := &Base{Key: key, Overhead: overhead, Param: param}
	// 与客户端 PickProtocol 一致:叠加协议注册 overhead(auth_chain_b 的 getRandLength 用 length+Overhead
	// 查 dataSizeList,不一致即 desync;auth_aes128/sha1_v4 也用 Overhead,虽小数据下影响不显)。
	if choice, ok := protocolList[name]; ok {
		b.Overhead += choice.overhead
	}
	switch name {
	case "auth_aes128_sha1":
		return newServerAuthAES128(newAuthAES128SHA1(b).(*authAES128), c, iv), nil
	case "auth_aes128_md5":
		return newServerAuthAES128(newAuthAES128MD5(b).(*authAES128), c, iv), nil
	case "auth_sha1_v4":
		p := newAuthSHA1V4(b).(*authSHA1V4)
		p.iv = iv
		return &Conn{Conn: c, Protocol: &serverAuthSHA1V4{authSHA1V4: p}}, nil
	case "auth_chain_a":
		p := newAuthChainA(b).(*authChainA)
		p.iv = iv
		p.packID = 1
		p.recvID = 1
		p.randDataLength = p.getRandLength
		return &Conn{Conn: c, Protocol: &serverAuthChainA{authChainA: p}}, nil
	case "auth_chain_b":
		pb := newAuthChainB(b).(*authChainB)
		pb.iv = iv
		pb.packID = 1
		pb.recvID = 1
		pb.initDataSize()                    // 按 Key 播种建 dataSizeList(与客户端一致)
		pb.randDataLength = pb.getRandLength // authChainB 的 getRandLength(用 dataSizeList)
		return &Conn{Conn: c, Protocol: &serverAuthChainA{authChainA: pb.authChainA}}, nil
	default:
		return nil, fmt.Errorf("ssr: 服务端暂不支持 protocol %q", name)
	}
}

// serverAuthChainA 是 authChainA 的服务端侧(角色互换):
//   - Decode(读客户端)镜像客户端 Encode —— lastClientHash 链 + randomClient + decrypter(与客户端
//     encrypter 同 RC4 key、逐字节同步)+ recvID(对齐客户端 packID);首 36 字节头 parseAuthHead。
//   - Encode(发客户端)镜像客户端 Decode 之源 —— lastServerHash 链 + randomServer + encrypter +
//     packID;首块前置 2 字节(客户端 Decode recvID==1 会剥)。
type serverAuthChainA struct {
	*authChainA
	gotHead   bool
	sentFirst bool
}

func (s *serverAuthChainA) StreamConn(c net.Conn, iv []byte) net.Conn { return c }

func (s *serverAuthChainA) Decode(dst, src *bytes.Buffer) error {
	if s.rawTrans {
		dst.ReadFrom(src)
		return nil
	}
	if !s.gotHead {
		if src.Len() < 36 {
			return nil
		}
		b := src.Bytes()
		macKey := make([]byte, len(s.iv)+len(s.Key))
		copy(macKey, s.iv)
		copy(macKey[len(s.iv):], s.Key)
		s.lastClientHash = tools.HmacMD5(macKey, b[:4])
		if !bytes.Equal(s.lastClientHash[:8], b[4:12]) {
			src.Reset()
			return errAuthChainChksumError
		}
		s.initRC4Cipher()
		s.lastServerHash = tools.HmacMD5(s.userKey, b[12:32])
		if !bytes.Equal(s.lastServerHash[:4], b[32:36]) {
			src.Reset()
			return errAuthChainChksumError
		}
		src.Next(36)
		s.gotHead = true
	}
	for src.Len() > 4 {
		b := src.Bytes()
		dataLength := int(binary.LittleEndian.Uint16(b[:2]) ^ binary.LittleEndian.Uint16(s.lastClientHash[14:16]))
		randDataLength := s.randDataLength(dataLength, s.lastClientHash, &s.randomClient)
		length := dataLength + randDataLength
		if dataLength < 0 || randDataLength < 0 || length < 0 {
			return errors.New("ssr: auth_chain_a 长度异常")
		}
		if length >= 4096 {
			s.rawTrans = true
			src.Reset()
			return errAuthChainLengthError
		}
		if 4+length > src.Len() {
			break
		}
		macKey := make([]byte, len(s.userKey)+4)
		copy(macKey, s.userKey)
		binary.LittleEndian.PutUint32(macKey[len(s.userKey):], s.recvID)
		clientHash := tools.HmacMD5(macKey, b[:length+2])
		if !bytes.Equal(clientHash[:2], b[length+2:length+4]) {
			s.rawTrans = true
			src.Reset()
			return errAuthChainChksumError
		}
		s.lastClientHash = clientHash
		pos := 2
		if dataLength > 0 && randDataLength > 0 {
			pos += getRandStartPos(randDataLength, &s.randomClient)
		}
		wanted := b[pos : pos+dataLength]
		s.decrypter.XORKeyStream(wanted, wanted)
		dst.Write(wanted)
		s.recvID++
		src.Next(length + 4)
	}
	return nil
}

func (s *serverAuthChainA) Encode(buf *bytes.Buffer, b []byte) error {
	if !s.sentFirst {
		s.sentFirst = true
		prefix := make([]byte, 2)
		_, _ = rand.Read(prefix)
		nb := make([]byte, 0, len(prefix)+len(b))
		nb = append(nb, prefix...)
		nb = append(nb, b...)
		b = nb
	}
	for len(b) > 2800 {
		s.packDataServer(buf, b[:2800])
		b = b[2800:]
	}
	if len(b) > 0 {
		s.packDataServer(buf, b)
	}
	return nil
}

// packDataServer 是客户端 packData 的服务端镜像(lastServerHash/randomServer/encrypter/packID)。
func (s *serverAuthChainA) packDataServer(buf *bytes.Buffer, data []byte) {
	s.encrypter.XORKeyStream(data, data)
	macKey := make([]byte, len(s.userKey)+4)
	copy(macKey, s.userKey)
	binary.LittleEndian.PutUint32(macKey[len(s.userKey):], s.packID)
	s.packID++
	length := uint16(len(data)) ^ binary.LittleEndian.Uint16(s.lastServerHash[14:16])
	orig := buf.Len()
	binary.Write(buf, binary.LittleEndian, length)
	randDataLength := s.randDataLength(len(data), s.lastServerHash, &s.randomServer)
	if len(data) == 0 {
		tools.AppendRandBytes(buf, randDataLength)
	} else if randDataLength > 0 {
		startPos := getRandStartPos(randDataLength, &s.randomServer)
		tools.AppendRandBytes(buf, startPos)
		buf.Write(data)
		tools.AppendRandBytes(buf, randDataLength-startPos)
	} else {
		buf.Write(data)
	}
	s.lastServerHash = tools.HmacMD5(macKey, buf.Bytes()[orig:])
	buf.Write(s.lastServerHash[:2])
}

// serverAuthSHA1V4 是 authSHA1V4 的服务端侧(chunk 无计数,Encode/Decode 直接复用客户端逻辑,
// 只在 Decode 前解一次 packAuthData 头)。
type serverAuthSHA1V4 struct {
	*authSHA1V4
	gotAuthHead bool
}

func (s *serverAuthSHA1V4) StreamConn(c net.Conn, iv []byte) net.Conn { return c }

func (s *serverAuthSHA1V4) Encode(buf *bytes.Buffer, b []byte) error {
	s.hasSentHeader = true
	return s.authSHA1V4.Encode(buf, b)
}

func (s *serverAuthSHA1V4) Decode(dst, src *bytes.Buffer) error {
	if !s.gotAuthHead {
		consumed, data, ok, err := s.parseAuthHead(src.Bytes())
		if err != nil {
			src.Reset()
			return err
		}
		if !ok {
			return nil
		}
		dst.Write(data)
		src.Next(consumed)
		s.gotAuthHead = true
	}
	return s.authSHA1V4.Decode(dst, src)
}

// parseAuthHead 是 auth_sha1_v4 packAuthData 的逆:
// [len(2)BE][crc32(4)LE of len+salt+key][randData 前缀+数据][authData(12)][data][hmacSHA1(10) of whole[:-10]]。
func (s *serverAuthSHA1V4) parseAuthHead(b []byte) (int, []byte, bool, error) {
	const minLen = 2 + 4 + 1 + 12 + 10
	if len(b) < minLen {
		return 0, nil, false, nil
	}
	packedAuthDataLength := int(binary.BigEndian.Uint16(b[:2]))
	if packedAuthDataLength < minLen || packedAuthDataLength > 8192 {
		return 0, nil, false, errAuthSHA1V4LengthError
	}
	if len(b) < packedAuthDataLength {
		return 0, nil, false, nil
	}
	// crc32([len(2)][salt][key]) == LE(b[2:6])
	salt := []byte("auth_sha1_v4")
	crcData := make([]byte, 2+len(salt)+len(s.Key))
	binary.BigEndian.PutUint16(crcData, uint16(packedAuthDataLength))
	copy(crcData[2:], salt)
	copy(crcData[2+len(salt):], s.Key)
	if crc32.ChecksumIEEE(crcData) != binary.LittleEndian.Uint32(b[2:6]) {
		return 0, nil, false, errAuthSHA1V4CRC32Error
	}
	// hmacSHA1(iv+key, whole[:-10])[:10] == 末 10 字节
	hkey := make([]byte, len(s.iv)+len(s.Key))
	copy(hkey, s.iv)
	copy(hkey[len(s.iv):], s.Key)
	if !bytes.Equal(tools.HmacSHA1(hkey, b[:packedAuthDataLength-10])[:10], b[packedAuthDataLength-10:packedAuthDataLength]) {
		return 0, nil, false, errAuthSHA1V4Adler32Error
	}
	// randData 前缀:<128 → 1 字节(值=randLen+1);否则 [0xff][BE uint16=randLen+3]
	var p int
	if b[6] < 128 {
		p = 7 + int(b[6]) - 1
	} else {
		if len(b) < 9 {
			return 0, nil, false, errAuthSHA1V4LengthError
		}
		p = 9 + int(binary.BigEndian.Uint16(b[7:9])) - 3
	}
	dataStart := p + 12 // 跳过 authData(12)
	dataEnd := packedAuthDataLength - 10
	if dataStart > dataEnd || dataStart > len(b) {
		return 0, nil, false, errAuthSHA1V4LengthError
	}
	return packedAuthDataLength, append([]byte(nil), b[dataStart:dataEnd]...), true, nil
}

func newServerAuthAES128(p *authAES128, c net.Conn, iv []byte) net.Conn {
	p.iv = iv
	p.packID = 1
	p.recvID = 1
	return &Conn{Conn: c, Protocol: &serverAuthAES128{authAES128: p}}
}

// serverAuthAES128 是 authAES128 的服务端侧:Encode 跳过 auth 头(纯 packData),Decode 先解 auth 头。
type serverAuthAES128 struct {
	*authAES128
	gotAuthHead bool
}

func (s *serverAuthAES128) StreamConn(c net.Conn, iv []byte) net.Conn { return c }

func (s *serverAuthAES128) Encode(buf *bytes.Buffer, b []byte) error {
	s.hasSentHeader = true // 服务端从不发 auth 头,强制走 packData
	return s.authAES128.Encode(buf, b)
}

func (s *serverAuthAES128) Decode(dst, src *bytes.Buffer) error {
	if !s.gotAuthHead {
		consumed, data, ok, err := s.parseAuthHead(src.Bytes())
		if err != nil {
			src.Reset()
			return err
		}
		if !ok {
			return nil // 头未收全,等更多字节(不消费 src)
		}
		dst.Write(data)
		src.Next(consumed)
		s.gotAuthHead = true
	}
	return s.authAES128.Decode(dst, src)
}

// parseAuthHead 是 packAuthData 的逆:验两道 hmac + AES-128-CBC 解出长度 + 抽内嵌首段数据。
// 返回 (消费字节数, 内嵌数据, 是否收全, 错误)。收全前 ok=false 且不报错时表示需更多字节。
func (s *serverAuthAES128) parseAuthHead(b []byte) (int, []byte, bool, error) {
	const fixed = 7 + 4 + 16 + 4 // checkHead+hmac6 / userID / encrypted / hmac4
	if len(b) < fixed {
		return 0, nil, false, nil
	}
	macKey := make([]byte, len(s.iv)+len(s.Key))
	copy(macKey, s.iv)
	copy(macKey[len(s.iv):], s.Key)

	// [0]=checkHead,[1:7]=hmac6(macKey, checkHead)
	if !bytes.Equal(s.hmac(macKey, b[0:1])[:6], b[1:7]) {
		return 0, nil, false, errAuthAES128MACError
	}
	// [7:11]=userID,[11:27]=encrypted,[27:31]=hmac4(macKey, userID+encrypted)
	if !bytes.Equal(s.hmac(macKey, b[7:27])[:4], b[27:31]) {
		return 0, nil, false, errAuthAES128MACError
	}

	userKey := s.userKey
	if len(userKey) == 0 {
		userKey = s.Key
	}
	cipherKey := sscore.Kdf(base64.StdEncoding.EncodeToString(userKey)+s.salt, 16)
	block, err := aes.NewCipher(cipherKey)
	if err != nil {
		return 0, nil, false, err
	}
	dec := make([]byte, 16)
	cipher.NewCBCDecrypter(block, make([]byte, 16)).CryptBlocks(dec, b[11:27])
	packedAuthDataLength := int(binary.LittleEndian.Uint16(dec[12:14]))
	randDataLength := int(binary.LittleEndian.Uint16(dec[14:16]))

	if packedAuthDataLength < fixed+randDataLength+4 || packedAuthDataLength > 8192 {
		return 0, nil, false, errAuthAES128LengthError
	}
	if len(b) < packedAuthDataLength {
		return 0, nil, false, nil // 需更多字节
	}
	// 全包末 4 字节 hmac4(userKey, whole[:-4])
	if !bytes.Equal(s.hmac(userKey, b[:packedAuthDataLength-4])[:4], b[packedAuthDataLength-4:packedAuthDataLength]) {
		return 0, nil, false, errAuthAES128ChksumError
	}
	dataStart := fixed + randDataLength
	dataEnd := packedAuthDataLength - 4
	if dataStart > dataEnd {
		return 0, nil, false, errAuthAES128LengthError
	}
	return packedAuthDataLength, append([]byte(nil), b[dataStart:dataEnd]...), true, nil
}
