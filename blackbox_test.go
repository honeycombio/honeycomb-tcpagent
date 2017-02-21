package main_test

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"net/http"
	"sync"
	"testing"

	"github.com/honeycombio/honeycomb-tcpagent/protocols/mongodb"
	"github.com/honeycombio/honeycomb-tcpagent/publish"
	"github.com/honeycombio/honeycomb-tcpagent/sniffer"
	libhoney "github.com/honeycombio/libhoney-go"
	"github.com/stretchr/testify/assert"
)

type testTransport struct {
	eventCount int
	sync.Mutex
}

func (tr *testTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	tr.Lock()
	tr.eventCount++
	tr.Unlock()
	return &http.Response{Body: ioutil.NopCloser(bytes.NewReader(nil)), StatusCode: 200}, nil
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
		transport := &testTransport{}
		libhoneyOptions := libhoney.Config{
			APIHost:   "http://localhost:9999",
			Dataset:   "test",
			WriteKey:  "test",
			Transport: transport,
		}
		tp := publish.NewBufferedPublisher(libhoneyOptions)

		pf := &mongodb.ParserFactory{
			Options:   mongodb.Options{Port: 27017},
			Publisher: tp,
		}
		s, _ := sniffer.New(options, pf)
		s.Run()
		transport.Lock()
		// TODO actually wait for all publishing to finish
		assert.True(b, transport.eventCount > 70000)
		fmt.Println("event count", transport.eventCount)
		transport.Unlock()
	}
}
