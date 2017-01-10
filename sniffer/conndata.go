package sniffer

import (
	"encoding/binary"
	"net"

	"github.com/emfree/gopacket"
)

type IPPortTuple struct {
	SrcIP   net.IP
	DstIP   net.IP
	SrcPort uint16
	DstPort uint16
}

func NewIPPortTuple(net_, transport gopacket.Flow) IPPortTuple {
	return IPPortTuple{
		SrcIP:   net.IP(net_.Src().Raw()),
		DstIP:   net.IP(net_.Dst().Raw()),
		SrcPort: binary.BigEndian.Uint16(transport.Src().Raw()),
		DstPort: binary.BigEndian.Uint16(transport.Dst().Raw()),
	}
}

func (t IPPortTuple) Reverse() IPPortTuple {
	return IPPortTuple{
		SrcIP:   t.DstIP,
		DstIP:   t.SrcIP,
		SrcPort: t.DstPort,
		DstPort: t.SrcPort,
	}
}
