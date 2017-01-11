package sniffer

import (
	"io"
	"sync"
	"time"

	"github.com/Sirupsen/logrus"
	"github.com/emfree/gopacket"
	"github.com/emfree/gopacket/layers"
	"github.com/emfree/gopacket/reassembly"
)

type Stream struct {
	consumer Consumer
	done     chan bool
	currDir  reassembly.TCPFlowDirection
	current  *Message
	messages chan *Message
	started  bool
	flow     IPPortTuple
	sync.Mutex
}

type Consumer interface {
	// TODO: Having to pass these Message objects around is kind of messy
	On(<-chan *Message)
}

// TODO: this is kind of a messy API
type ConsumerFactory interface {
	New(flow IPPortTuple) Consumer
	BPFFilter() string
}

// TODO: need to handle gaps!
func (s *Stream) ReassembledSG(sg reassembly.ScatterGather, ac reassembly.AssemblerContext) {
	dir, _, _, _ := sg.Info()

	length, _ := sg.Lengths()
	data := sg.Fetch(length)
	if s.started && s.currDir == dir {
		s.current.bytes <- data
	} else {
		if s.started {
			close(s.current.bytes)
		}
		s.started = true
		s.currDir = dir
		s.current = &Message{
			Flow:      s.getFlow(dir),
			Timestamp: ac.GetCaptureInfo().Timestamp,
			bytes:     make(chan []byte),
		}
		s.messages <- s.current
		s.current.bytes <- data
	}
}

type Message struct {
	Flow      IPPortTuple
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

// TODO: ensure this fully handles completion
func (s *Stream) ReassemblyComplete(ac reassembly.AssemblerContext) bool {
	logrus.WithField("flow", s.flow).Debug("Closing stream")
	close(s.messages)
	// TODO: make sure this can't ever race
	if s.current != nil {
		close(s.current.bytes)
	}
	return false
}

func (s *Stream) Accept(tcp *layers.TCP, ci gopacket.CaptureInfo, dir reassembly.TCPFlowDirection,
	ackSeq reassembly.Sequence, start *bool, ac reassembly.AssemblerContext) bool {
	// TODO?
	return true
}

func (s *Stream) getFlow(dir reassembly.TCPFlowDirection) IPPortTuple {
	// TCPDirClientToServer means the direction of the half-connection that was
	// first seen. That's not actually necessarily the true client-to-server
	// direction. We use this helper to pass the correct IPPortTuple object on
	// to the consumer in ReassembledSG.
	if dir == reassembly.TCPDirClientToServer {
		return s.flow
	} else {
		return s.flow.Reverse()
	}
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
	flow := NewIPPortTuple(net, transport)
	s := &Stream{flow: flow, messages: make(chan *Message)}
	s.consumer = f.cf.New(flow)
	logrus.WithFields(logrus.Fields{"flow": flow}).Debug("Creating new stream")
	go s.consumer.On(s.messages)
	return s
}

type Context struct {
	CaptureInfo gopacket.CaptureInfo
}

func (c *Context) GetCaptureInfo() gopacket.CaptureInfo {
	return c.CaptureInfo
}
