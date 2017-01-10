package protocols

import (
	"encoding/binary"
	"io"
	"net"
	"time"

	"github.com/google/gopacket"
)

type Consumer interface {
	On(isClient bool, ts time.Time, stream io.Reader)
}

// TODO: this is a bad API
type ConsumerFactory interface {
	New(flow IPPortTuple) Consumer
	IsClient(net, transport gopacket.Flow) bool
	BPFFilter() string
}

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
