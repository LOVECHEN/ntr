package tlsmirror

import "encoding/binary"

// packPadding 在明文尾追加 paddingLength 字节 0 + 4B BE 原长(传输层填充,抗长度指纹)。逐字节承 mihomo。
func packPadding(data []byte, paddingLength int) []byte {
	dataLength := len(data)
	data = append(data, make([]byte, paddingLength)...)
	data = binary.BigEndian.AppendUint32(data, uint32(dataLength))
	return data
}

// unpackPadding 剥填充:尾 4B 为原长,取回明文。返回 (明文, 填充长度);非法返回 nil。
func unpackPadding(data []byte) ([]byte, int) {
	dataLength := len(data)
	if dataLength < 4 {
		return nil, dataLength
	}
	payloadLength := int(binary.BigEndian.Uint32(data[dataLength-4:]))
	if payloadLength > dataLength-4 {
		return nil, 0
	}
	paddingLength := dataLength - payloadLength - 4
	if paddingLength < 0 {
		return nil, paddingLength
	}
	return data[:payloadLength], paddingLength
}
