package sniffer

import (
	"io"
	"sync"
	"time"

	"github.com/emfree/gopacket"
	"github.com/emfree/gopacket/layers"
	"github.com/emfree/gopacket/reassembly"
)

type Stream struct {
	consumer Consumer
	done     chan bool
	current  *Message
	messages chan *Message
	started  bool
	reversed bool
	sync.Mutex
}

type Consumer interface {
	// TODO: Having to pass these Message objects around is kind of messy
	On(<-chan *Message)
}

// TODO: this is kind of a messy API
type ConsumerFactory interface {
	New(flow IPPortTuple) Consumer
	IsClient(net, transport gopacket.Flow) bool
	BPFFilter() string
}

// TODO: need to handle gaps!
func (s *Stream) ReassembledSG(sg reassembly.ScatterGather, ac reassembly.AssemblerContext) {
	dir, _, _, _ := sg.Info()
	client := s.isClient(bool(dir))

	length, _ := sg.Lengths()
	data := sg.Fetch(length)
	if s.started && s.current.IsClient == client {
		s.current.bytes <- data
	} else {
		if s.started {
			close(s.current.bytes)
		}
		s.started = true
		s.current = &Message{
			IsClient:  client,
			Timestamp: ac.GetCaptureInfo().Timestamp,
			bytes:     make(chan []byte),
		}
		s.messages <- s.current
		s.current.bytes <- data
	}
}

func (s *Stream) isClient(dir bool) bool {
	// TODO: audit
	return s.reversed != dir
}

type Message struct {
	IsClient  bool
	Timestamp time.Time
	bytes     chan []byte
	current   []byte
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
func (s *Stream) ReassemblyComplete(ac reassembly.AssemblerContext) bool {
	return false
}

func (s *Stream) Accept(tcp *layers.TCP, ci gopacket.CaptureInfo, dir reassembly.TCPFlowDirection,
	ackSeq reassembly.Sequence, start *bool, ac reassembly.AssemblerContext) bool {
	// TODO?
	return true
}

type streamFactory struct {
	cf ConsumerFactory
	sync.Mutex
}

func NewStreamFactory(cf ConsumerFactory) *streamFactory {
	return &streamFactory{
		cf: cf,
	}
}

func (f *streamFactory) New(net, transport gopacket.Flow, tcp *layers.TCP, ac reassembly.AssemblerContext) reassembly.Stream {
	reversed := f.cf.IsClient(net, transport)
	s := &Stream{reversed: reversed, messages: make(chan *Message)}
	flow := NewIPPortTuple(net, transport)
	s.consumer = f.cf.New(flow)
	go s.consumer.On(s.messages)
	return s
}

type Context struct {
	CaptureInfo gopacket.CaptureInfo
}

func (c *Context) GetCaptureInfo() gopacket.CaptureInfo {
	return c.CaptureInfo
}
