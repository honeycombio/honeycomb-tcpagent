package sniffer

import (
	"io"
	"sync"
	"time"

	"github.com/Sirupsen/logrus"
	"github.com/google/gopacket"
	"github.com/google/gopacket/tcpassembly"
	"github.com/honeycombio/honeypacket/protocols"
)

type BidiStream struct {
	// The client stream contains packets going *to* the client, and vice versa
	// TODO: name these better
	client, server *stream
	consumer       protocols.Consumer
	done           chan bool
	current        *Message
	started        bool
	sync.Mutex
}

func (b *BidiStream) Reassembled(client bool, rs []tcpassembly.Reassembly) {
	b.Lock()
	defer b.Unlock()
	if b.started && b.current.isClient == client {
		for _, r := range rs {
			b.current.bytes <- r.Bytes
		}
	} else {
		if b.started {
			close(b.current.bytes)
		}
		logrus.Debug("Creating new reader stream")
		b.started = true
		b.current = &Message{
			isClient: client,
			ts:       rs[0].Seen,
			bytes:    make(chan []byte),
		}
		// TODO: make sure len(rs) > 0
		go b.consumer.On(client, rs[0].Seen, b.current)
		for _, r := range rs {
			b.current.bytes <- r.Bytes
		}
	}
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

// TODO
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
	k := key{net, transport}
	isClient := f.cf.IsClient(net, transport)
	s := &stream{key: k, isClient: isClient}

	bd := f.bidiMap[k]
	if bd == nil {
		bd = f.newBidiStream(net, transport)
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

func (bf *bidiFactory) newBidiStream(net, transport gopacket.Flow) *BidiStream {
	b := &BidiStream{}
	b.consumer = bf.cf.New(net, transport)
	return b
}

func (s *stream) Reassembled(rs []tcpassembly.Reassembly) {
	s.bidi.Reassembled(s.isClient, rs)
}

func (s *stream) ReassemblyComplete() {}

// TODO: need to handle completion
