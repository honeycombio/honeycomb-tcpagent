package protocols

import "net"

type PacketInfo struct {
	SrcIP, DstIP     net.IP
	SrcPort, DstPort uint16
	Data             []byte
	Truncated        bool
}

type Consumer interface {
	Handle(PacketInfo) // TODO: better name
}
