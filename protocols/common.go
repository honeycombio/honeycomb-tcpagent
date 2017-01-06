package protocols

import (
	"net"
	"time"

	"github.com/Sirupsen/logrus"
	"github.com/google/gopacket/tcpassembly"
)

type PacketInfo struct {
	Timestamp        time.Time
	SrcIP, DstIP     net.IP
	SrcPort, DstPort uint16
	Data             []byte
	Truncated        bool
}

func (p *PacketInfo) ToFields() logrus.Fields {
	fields := make(logrus.Fields)
	fields["Timestamp"] = p.Timestamp
	fields["srcIP"] = p.SrcIP
	fields["dstIP"] = p.DstIP
	fields["truncated"] = p.Truncated
	fields["data"] = p.Data
	return fields
}

type Consumer interface {
	On(bool, tcpassembly.Reassembly)
}

type ConsumerFactory interface {
	New() Consumer
}
