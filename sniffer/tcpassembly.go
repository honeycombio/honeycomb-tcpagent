package sniffer

import (
	"fmt"

	"github.com/google/gopacket"
	"github.com/google/gopacket/tcpassembly"
	"github.com/honeycombio/honeypacket/protocols"
)

type BidiStream struct {
	// The client stream contains packets going *to* the client, and vice versa
	// TODO: name these better
	client, server *stream
	consumer       protocols.Consumer
}

func (b *BidiStream) Reassembled(client bool, rs []tcpassembly.Reassembly) {
	// debug
	for _, r := range rs {
		b.consumer.On(client, r)
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
	cf      protocols.ConsumerFactory
}

func NewBidiFactory(cf protocols.ConsumerFactory) *bidiFactory {
	return &bidiFactory{
		bidiMap: map[key]*BidiStream{},
		cf:      cf,
	}
}

func (f *bidiFactory) New(net, transport gopacket.Flow) tcpassembly.Stream {
	fmt.Println("New stream", net, transport)
	k := key{net, transport}
	isClient := f.cf.IsClient(net, transport)
	s := &stream{key: k, isClient: isClient}

	bd := f.bidiMap[k]
	if bd == nil {
		bd = f.newBidiStream()
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

func (f *bidiFactory) newBidiStream() *BidiStream {
	bds := &BidiStream{}
	bds.consumer = f.cf.New()
	return bds

}

func (s *stream) Reassembled(rs []tcpassembly.Reassembly) {
	s.bidi.Reassembled(s.isClient, rs)
}

func (s *stream) ReassemblyComplete() {}

// TODO: need to handle completion