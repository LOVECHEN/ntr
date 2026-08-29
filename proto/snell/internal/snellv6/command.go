package snellv6

import (
	"encoding/binary"
	"fmt"
)

// snell application command bytes (stage-S0 request header).
const (
	cmdPing    = 0 // PING -> server replies pong (0x01)
	cmdConnect = 1 // CONNECT (single-use)
	cmdUDP     = 6 // UDP relay
	// command 5 (== cmdConnect | 0x04) is CONNECT with tunnel reuse.
)

// command is a decoded stage-S0 request header.
type command struct {
	command  byte
	clientID string
	host     string
	port     uint16
}

// parseCommand decodes the stage-S0 request header (sub_3F640). Returns
// (nil,0,nil) when more bytes are needed, or an error for malformed input.
//
//	[0] version=1  [1] command
//	command!=0: [2] idLen, clientID, [n] hostLen, host, port(u16 BE), data
func parseCommand(b []byte) (*command, int, error) {
	if len(b) < 2 {
		return nil, 0, nil
	}
	if b[0] != 1 {
		return nil, 0, fmt.Errorf("snellv6: bad version %d (want 1)", b[0])
	}
	cmd := b[1]
	if cmd == cmdPing {
		return &command{command: cmdPing}, 2, nil
	}
	if cmd&0xFB != 1 && cmd != cmdUDP {
		return nil, 0, fmt.Errorf("snellv6: unknown command %d", cmd)
	}
	// commands 1/5/6 carry [idLen][clientID] next.
	if len(b) < 3 {
		return nil, 0, nil
	}
	idLen := int(b[2])
	p := 3 + idLen
	if len(b) < p {
		return nil, 0, nil
	}
	clientID := string(b[3:p])
	if cmd == cmdUDP {
		return &command{command: cmdUDP, clientID: clientID}, p, nil
	}
	// command 1/5: connect — needs hostLen + host + port
	if len(b) < p+1 {
		return nil, 0, nil
	}
	hostLen := int(b[p])
	q := p + 1 + hostLen
	if len(b) < q+2 {
		return nil, 0, nil
	}
	host := string(b[p+1 : q])
	port := binary.BigEndian.Uint16(b[q : q+2])
	return &command{command: cmd, clientID: clientID, host: host, port: port}, q + 2, nil
}
