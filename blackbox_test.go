package main_test

import (
	"fmt"
	"sync"
	"testing"

	"github.com/honeycombio/honeypacket/protocols/mongodb"
	"github.com/honeycombio/honeypacket/sniffer"
	"github.com/stretchr/testify/assert"
)

type testPublisher struct {
	output [][]byte
}

func (tp *testPublisher) Publish(m []byte) bool {
	tp.output = append(tp.output, m)
	return true
}

type nullPublisher struct{}

func (np *nullPublisher) Publish([]byte) bool { return true }

func TestIngestion(t *testing.T) {
	options := sniffer.Options{
		SourceType:   "offline",
		Device:       "any",
		SnapLen:      65535,
		BufSizeMb:    30,
		FlushTimeout: 60,
		PcapFile:     "testdata/tcpd_any.pcap",
	}
	m := &sync.Mutex{}
	tp := &testPublisher{
		output: make([][]byte, 0),
	}

	pf := &mongodb.ParserFactory{
		Options:   mongodb.Options{Port: 27017},
		Publisher: tp,
	}
	s, _ := sniffer.New(options, pf)
	s.Run()
	m.Lock()
	// TODO what's wrong here?
	assert.True(t, len(tp.output) > 70000)
	fmt.Println("output length", len(tp.output))
	m.Unlock()
}

func BenchmarkIngestion(b *testing.B) {
	options := sniffer.Options{
		SourceType:   "offline",
		Device:       "any",
		SnapLen:      65535,
		BufSizeMb:    30,
		FlushTimeout: 60,
		PcapFile:     "testdata/tcpd_any.pcap",
	}

	for i := 0; i < b.N; i++ {
		pf := &mongodb.ParserFactory{
			Options:   mongodb.Options{Port: 27017},
			Publisher: &nullPublisher{},
		}
		s, _ := sniffer.New(options, pf)
		s.Run()
	}
}
