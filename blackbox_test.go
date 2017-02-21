package main_test

import (
	"bytes"
	"encoding/json"
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

type testPublisher struct {
	eventCount uint64
	sync.Mutex
}

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

func (tp *testPublisher) Publish(data interface{}) {
	tp.Lock()
	json.Marshal(data)
	tp.eventCount++
	tp.Unlock()
}

func TestIngestion(t *testing.T) {
	options := sniffer.Options{
		SourceType:   "offline",
		Device:       "any",
		SnapLen:      65535,
		BufSizeMb:    30,
		FlushTimeout: 60,
		PcapFile:     "testdata/tcpd_any.pcap",
	}
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
	assert.True(t, transport.eventCount > 70000)
	fmt.Println("event count", transport.eventCount)
	transport.Unlock()
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
			Publisher: &testPublisher{},
		}
		s, _ := sniffer.New(options, pf)
		s.Run()
	}
}
