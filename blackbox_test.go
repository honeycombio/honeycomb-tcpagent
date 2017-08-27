package main_test

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/honeycombio/honeycomb-tcpagent/protocols/mongodb"
	"github.com/honeycombio/honeycomb-tcpagent/sniffer"
	"github.com/stretchr/testify/assert"
)

type testPublisher struct {
	eventCount int
	sync.Mutex
}

func (tp *testPublisher) Publish(data interface{}, timestamp time.Time) {
	tp.Lock()
	tp.eventCount++
	tp.Unlock()
}

// TODO: this needs some work. The benchmark currently elides serialization,
// which happens in libhoney. We should also have a similar benchmark for
// MySQL.
func BenchmarkIngestion(b *testing.B) {
	// Read from a pcap file containing ~100K MongoDB queries
	options := sniffer.Options{
		SourceType:   "offline",
		Device:       "any",
		SnapLen:      65535,
		BufSizeMb:    30,
		FlushTimeout: 60,
		PcapFile:     "testdata/tcpd_any.pcap",
	}

	for i := 0; i < b.N; i++ {
		tp := &testPublisher{}

		pf := &mongodb.ParserFactory{
			Options:   mongodb.Options{Port: 27017},
			Publisher: tp,
		}
		s, _ := sniffer.New(options, pf)
		s.Run()
		tp.Lock()
		// TODO actually wait for all publishing to finish
		assert.True(b, tp.eventCount > 70000)
		fmt.Println("event count", tp.eventCount)
		tp.Unlock()
	}
}
