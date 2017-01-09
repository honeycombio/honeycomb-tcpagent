package protocols

import (
	"io"
	"time"

	"github.com/google/gopacket"
)

type Consumer interface {
	On(isClient bool, ts time.Time, stream io.Reader)
}

// TODO: this is a bad API
type ConsumerFactory interface {
	New(net, transport gopacket.Flow) Consumer
	IsClient(net, transport gopacket.Flow) bool
	BPFFilter() string
}
