package sniffer

import (
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/emfree/gopacket"
	"github.com/emfree/gopacket/layers"
	"github.com/emfree/gopacket/reassembly"
	"github.com/honeycombio/honeypacket/protocols"
)

type BidiStream struct {
	// The client stream contains packets going *to* the client, and vice versa
	// TODO: name these better
	consumer protocols.Consumer
	done     chan bool
	current  *Message
	started  bool
	reversed bool
	sync.Mutex
}

func (b *BidiStream) ReassembledSG(sg reassembly.ScatterGather, ac reassembly.AssemblerContext) {
	b.Lock()
	defer b.Unlock()

	dir, _, _, _ := sg.Info()
	client := b.isClient(bool(dir))

	length, _ := sg.Lengths()
	data := sg.Fetch(length)
	if b.started && b.current.isClient == client {
		b.current.bytes <- data
	} else {
		if b.started {
			close(b.current.bytes)
		}
		b.started = true
		b.current = &Message{
			isClient: client,
			ts:       ac.GetCaptureInfo().Timestamp,
			bytes:    make(chan []byte),
		}
		go b.consumer.On(client, ac.GetCaptureInfo().Timestamp, b.current)
		// ^ TODO: we should wrap this and make sure to discard any remaining
		// bytes that it leaves
		// debug
		fmt.Println("FEEDING BYTES", data)
		b.current.bytes <- data
	}
}

func (b *BidiStream) isClient(dir bool) bool {
	return b.reversed != dir
}

type Message struct {
	isClient bool
	ts       time.Time
	bytes    chan []byte
	current  []byte
}

func (m *Message) Read(p []byte) (int, error) {
	ok := true
	for ok && len(m.current) == 0 {
		m.current, ok = <-m.bytes
	}
	if !ok || len(m.current) == 0 {
		return 0, io.EOF
	}
	l := copy(p, m.current)
	m.current = m.current[l:]
	return l, nil
}

// TODO: need to handle completion
func (b *BidiStream) ReassemblyComplete(ac reassembly.AssemblerContext) bool {
	return false
}

func (b *BidiStream) Accept(tcp *layers.TCP, ci gopacket.CaptureInfo, dir reassembly.TCPFlowDirection,
	ackSeq reassembly.Sequence, start *bool, ac reassembly.AssemblerContext) bool {
	// TODO?
	return true
}

type bidiFactory struct {
	cf protocols.ConsumerFactory
	sync.Mutex
}

func NewBidiFactory(cf protocols.ConsumerFactory) *bidiFactory {
	return &bidiFactory{
		cf: cf,
	}
}

func (f *bidiFactory) New(net, transport gopacket.Flow, tcp *layers.TCP, ac reassembly.AssemblerContext) reassembly.Stream {
	reversed := f.cf.IsClient(net, transport)
	return f.newBidiStream(net, transport, reversed)
}

func (f *bidiFactory) newBidiStream(net, transport gopacket.Flow, reversed bool) *BidiStream {
	b := &BidiStream{reversed: reversed}
	flow := protocols.NewIPPortTuple(net, transport)
	b.consumer = f.cf.New(flow)
	return b
}

type Context struct {
	CaptureInfo gopacket.CaptureInfo
}

func (c *Context) GetCaptureInfo() gopacket.CaptureInfo {
	return c.CaptureInfo
}
