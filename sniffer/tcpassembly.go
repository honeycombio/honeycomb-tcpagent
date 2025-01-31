package sniffer

import (
	"io"
	"sync"
	"time"

	"github.com/Sirupsen/logrus"
	"github.com/codahale/metrics"
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

// A Message represents a concatenated sequence of one or more consecutive TCP
// segments in one direction.
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
	sync.Mutex
}

func (s *Stream) ReassembledSG(sg reassembly.ScatterGather, ac reassembly.AssemblerContext) {
	dir, _, _, skipped := sg.Info()

	length, _ := sg.Lengths()
	data := sg.Fetch(length)

	// It's been reported that ac.GetCaptureInfo().Timestamp very rarely fails
	// with a nil pointer error. Absent a reasonable strategy for tracking down
	// the underlying issue in gopacket, check for this condition.
	var timestamp time.Time
	if ac != nil {
		timestamp = ac.GetCaptureInfo().Timestamp
	} else {
		logrus.WithFields(logrus.Fields{
			"skipped": skipped,
			"ac":      ac,
			"flow":    s.getFlow(dir),
		}).Error("Missing capture info")
	}
	if skipped == 0 && s.started && s.currDir == dir {
		s.current.bytes <- data
	} else {
		// End the current message and create a new one whenever the direction
		// changes, or we've skipped segments.
		if s.started {
			close(s.current.bytes)
		}
		s.started = true

		if skipped > 0 {
			logrus.WithFields(logrus.Fields{
				"skipped": skipped,
				"flow":    s.getFlow(dir)}).Debug("Skipped bytes in stream")
			metrics.Counter("sniffer.bytes_skipped").AddN(uint64(skipped))
		}
		metrics.Counter("sniffer.bytes_processed").AddN(uint64(length))

		s.currDir = dir
		s.Lock()
		s.current = &message{
			flow:      s.getFlow(dir),
			timestamp: timestamp,
			bytes:     make(chan []byte, 32),
		}
		s.Unlock()
		s.messages <- s.current
		s.current.bytes <- data
	}
	metrics.Counter("sniffer.reassembledsg_calls").Add()
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
	s.Lock()
	if s.current != nil {
		close(s.current.bytes)
	}
	s.Unlock()
	metrics.Counter("streams.complete").Add()
	return false
}

func (s *Stream) Accept(tcp *layers.TCP, ci gopacket.CaptureInfo, dir reassembly.TCPFlowDirection,
	ackSeq reassembly.Sequence, start *bool, ac reassembly.AssemblerContext) bool {
	// Don't require a SYN; always start processing a new connection we see.
	// This means that we need to be fully robust against parsing bad packets,
	// but allows us to capture data on existing connections as soon as we
	// start up -- which is common if you have long-lived connection pools to
	// your database.
	*start = true
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
	s := &Stream{
		flow:     flow,
		messages: make(chan *message, 32),
	}
	s.consumer = f.cf.New(flow)
	logrus.WithFields(logrus.Fields{"flow": flow}).Debug("Creating new stream")
	go s.consumer.On(s)
	metrics.Counter("streams.started").Add()
	return s
}

type Context struct {
	CaptureInfo gopacket.CaptureInfo
}

func (c *Context) GetCaptureInfo() gopacket.CaptureInfo {
	return c.CaptureInfo
}
