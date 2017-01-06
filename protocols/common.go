package protocols

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/tcpassembly"
)

type Consumer interface {
	On(bool, tcpassembly.Reassembly)
}

// TODO: this is a bad API
type ConsumerFactory interface {
	New() Consumer
	IsClient(net, transport gopacket.Flow) bool
	BPFFilter() string
}
