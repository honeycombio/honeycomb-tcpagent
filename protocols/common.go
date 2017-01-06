package protocols

import "github.com/google/gopacket/tcpassembly"

type Consumer interface {
	On(bool, tcpassembly.Reassembly)
}

type ConsumerFactory interface {
	New() Consumer
}
