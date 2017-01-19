package blackbox_test

import (
	"fmt"
	"sync"
	"testing"

	"github.com/honeycombio/honeypacket/protocols/mongodb"
	"github.com/honeycombio/honeypacket/sniffer"
	"github.com/stretchr/testify/assert"
)

func TestIngestion(t *testing.T) {
	options := sniffer.Options{
		SourceType:   "offline",
		Device:       "any",
		SnapLen:      65535,
		BufSizeMb:    30,
		FlushTimeout: 60,
		PcapFile:     "testdata/tcpd_any.pcap",
	}
	output := make([][]byte, 0)
	m := &sync.Mutex{}
	cb := func(b []byte) {
		m.Lock()
		output = append(output, b)
		m.Unlock()
	}

	pf := &mongodb.ParserFactory{
		Options:     mongodb.Options{Port: 27017},
		PublishFunc: cb,
	}
	s, _ := sniffer.New(options, pf)
	s.Run()
	m.Lock()
	// TODO what's wrong here?
	assert.True(t, len(output) > 70000)
	fmt.Println("output length", len(output))
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
			Options:     mongodb.Options{Port: 27017},
			PublishFunc: func([]byte) {},
		}
		s, _ := sniffer.New(options, pf)
		s.Run()
	}
}
