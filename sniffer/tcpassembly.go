package sniffer

import (
	"fmt"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/tcpassembly"
)

type BidiStream struct {
	// The client stream contains packets going *to* the client, and vice versa
	// TODO: name these better
	client, server *stream
}

func NewBidiStream() {
}

func (b *BidiStream) Reassembled(client bool, rs []tcpassembly.Reassembly) {
	// debug
	fmt.Println("Calling bidi.reassembled")
	for _, r := range rs {
		fmt.Println("Reassembled packet", r)
	}
}

func (b *BidiStream) ReassemblyComplete() {}

type key struct {
	net, transport gopacket.Flow
}

type stream struct {
	isClient bool
	bidi     *BidiStream
	done     bool
	key      key
}

type bidiFactory struct {
	bidiMap map[key]*BidiStream
}

func (f *bidiFactory) New(net, transport gopacket.Flow) tcpassembly.Stream {
	fmt.Println("New stream", net, transport)
	k := key{net, transport}
	// TODO: inject this condition
	isClient := transport.Src() == layers.NewTCPPortEndpoint(layers.TCPPort(3306))
	s := &stream{key: k, isClient: isClient}

	bd := f.bidiMap[k]
	if bd == nil {
		bd = &BidiStream{}
		f.bidiMap[key{net.Reverse(), transport.Reverse()}] = bd
	} else {
		delete(f.bidiMap, k)
	}

	if isClient {
		bd.client = s
	} else {
		bd.server = s
	}
	s.bidi = bd
	return s

}

func (s *stream) Reassembled(rs []tcpassembly.Reassembly) {
	fmt.Println("calling s.reassembled", s.key.net, s.key.transport)
	s.bidi.Reassembled(s.isClient, rs)
}

func (s *stream) ReassemblyComplete() {}

// TODO: need to handle completion
