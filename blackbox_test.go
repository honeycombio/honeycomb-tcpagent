package main_test

import (
	"fmt"
	"sync"
	"testing"

	"github.com/honeycombio/honeycomb-tcpagent/protocols/mongodb"
	"github.com/honeycombio/honeycomb-tcpagent/sniffer"
	"github.com/stretchr/testify/assert"
)

type testPublisher struct {
	eventCount uint64
	sync.Mutex
}

func (tp *testPublisher) Publish([]byte) bool {
	tp.Lock()
	tp.eventCount++
	tp.Unlock()
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
	tp := &testPublisher{}

	pf := &mongodb.ParserFactory{
		Options:   mongodb.Options{Port: 27017},
		Publisher: tp,
	}
	s, _ := sniffer.New(options, pf)
	s.Run()
	m.Lock()
	// TODO actually wait for all publishing to finish
	assert.True(t, tp.eventCount > 70000)
	fmt.Println("event count", tp.eventCount)
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
