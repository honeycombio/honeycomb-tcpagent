package sniffer

import (
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/Sirupsen/logrus"
	"github.com/emfree/gopacket"
	"github.com/emfree/gopacket/layers"
	"github.com/emfree/gopacket/reassembly"
)

type Consumer interface {
	On(MessageStream)
}

// TODO: this is kind of a messy API
type ConsumerFactory interface {
	New(flow IPPortTuple) Consumer
	BPFFilter() string
}

type Message interface {
	Timestamp() time.Time
	Flow() IPPortTuple
	io.Reader
}

type MessageStream interface {
	Next() (Message, bool)
}

type Stream struct {
	consumer Consumer
	done     chan bool
	currDir  reassembly.TCPFlowDirection
	current  *message
	messages chan *message
	started  bool
	flow     IPPortTuple
}

// TODO: need to handle gaps!
func (s *Stream) ReassembledSG(sg reassembly.ScatterGather, ac reassembly.AssemblerContext) {
	dir, start, end, skip := sg.Info()

	length, _ := sg.Lengths()
	data := sg.Fetch(length)
	fmt.Println("CALLED REASSEMBLED", dir, start, end, skip, data)
	if s.started && s.currDir == dir {
		s.current.bytes <- data
	} else {
		fmt.Println("STARTING NEW MESSAGE")
		if s.started {
			close(s.current.bytes)
		}
		s.started = true
		s.currDir = dir
		s.current = &message{
			flow:      s.getFlow(dir),
			timestamp: ac.GetCaptureInfo().Timestamp,
			bytes:     make(chan []byte),
		}
		s.messages <- s.current
		s.current.bytes <- data
	}
	fmt.Println("REASSEMBLY DONE")
}

// Implements Message
// TODO: restructure a bit?
type message struct {
	flow      IPPortTuple
	timestamp time.Time
	bytes     chan []byte
	current   []byte
}

func (m *message) Timestamp() time.Time {
	return m.timestamp
}

func (m *message) Flow() IPPortTuple {
	return m.flow
}

func (m *message) Read(p []byte) (int, error) {
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
	// should modify start to start stream even if no SYN has been seen!
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

// Implements the MessageStream interface
func (s *Stream) Next() (Message, bool) {
	m, ok := <-s.messages
	return m, ok
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
	s := &Stream{flow: flow, messages: make(chan *message)}
	s.consumer = f.cf.New(flow)
	logrus.WithFields(logrus.Fields{"flow": flow}).Debug("Creating new stream")
	go s.consumer.On(s)
	return s
}

type Context struct {
	CaptureInfo gopacket.CaptureInfo
}

func (c *Context) GetCaptureInfo() gopacket.CaptureInfo {
	return c.CaptureInfo
}
