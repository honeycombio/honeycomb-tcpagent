package mongodb

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/honeycombio/honeypacket/publish"
	"github.com/honeycombio/honeypacket/sniffer"
	"github.com/stretchr/testify/assert"

	"gopkg.in/mgo.v2/bson"
)

func TestParseFind(t *testing.T) {
	tp := &testPublisher{}
	parser := newParser(tp)

	collectionName := "db.$cmd"
	var find map[string]interface{}
	err := json.Unmarshal([]byte(`{
		"find":   "collection0",
		"filter": {"rating": {"$gte": 9}, "cuisine": "italian"}
	}`), &find)
	assert.Nil(t, err)

	var reply map[string]interface{}
	ts := time.Date(2006, 1, 2, 15, 4, 5, 0, time.UTC)
	request := genQuery(collectionName, find)
	response := genReply(reply)
	ms := &messageStream{}
	ms.Append(request, ts, defaultFlow())
	ms.Append(response, ts, defaultFlow().Reverse())
	parser.On(ms)
	assert.Equal(t, 1, len(tp.output))
	var ret map[string]interface{}
	json.Unmarshal(tp.output[0], &ret)
	assert.Equal(t, "find", ret["CommandType"])
	assert.Equal(t, `{"filter":{"cuisine":"italian","rating":{"$gte":9}},"find":"collection0"}`, ret["Command"])
}

func TestTruncateLongCommands(t *testing.T) {
	tp := &testPublisher{}
	parser := newParser(tp)

	collectionName := "db.$cmd"
	var find map[string]interface{}
	err := json.Unmarshal([]byte(fmt.Sprintf(`{
		"insert":   "collection0",
		"documents": [{"key": "%s"}]
	}`, strings.Repeat("x", 2048))), &find)
	assert.Nil(t, err)

	var reply map[string]interface{}
	ts := time.Date(2006, 1, 2, 15, 4, 5, 0, time.UTC)
	request := genQuery(collectionName, find)
	response := genReply(reply)
	ms := &messageStream{}
	ms.Append(request, ts, defaultFlow())
	ms.Append(response, ts, defaultFlow().Reverse())
	parser.On(ms)
	assert.Equal(t, 1, len(tp.output))
	var ret map[string]interface{}
	json.Unmarshal(tp.output[0], &ret)
	assert.Equal(t, "insert", ret["CommandType"])
	assert.True(t, len(tp.output[0]) > 0)
	assert.True(t, len(tp.output[0]) < 800)
}

func TestParseOldInsert(t *testing.T) {
	tp := &testPublisher{}
	parser := newParser(tp)
	// TODO: better injection of test message data
	collectionName := "db.collection0"
	doc := map[string]interface{}{"a": "b"}
	insert := genOldStyleInsert(collectionName, doc)
	ts := time.Date(2006, 1, 2, 15, 4, 5, 0, time.UTC)
	ms := &messageStream{}
	ms.Append(insert, ts, defaultFlow())
	parser.On(ms)
	assert.Equal(t, len(tp.output), 1)
	var ret map[string]interface{}
	json.Unmarshal(tp.output[0], &ret)
	assert.Equal(t, ret["CommandType"], "insert")
	assert.Equal(t, ret["NInserted"], float64(1))
	assert.Equal(t, ret["ClientIP"], "10.0.0.22")
	assert.Equal(t, ret["ServerIP"], "10.0.0.23")
	assert.Equal(t, ret["Collection"], "collection0")
	assert.Equal(t, ret["Database"], "db")
	assert.Equal(t, ret["Namespace"], "db.collection0")
	assert.Equal(t, ret["Timestamp"], "2006-01-02T15:04:05Z")
}

func genQuery(collectionName string, document interface{}) []byte {
	cname := append([]byte(collectionName), '\x00')
	serializedDoc, _ := bson.Marshal(document)
	length := uint32(16 + 4 + len(cname) + 8 + len(serializedDoc))
	prologue := struct {
		messageLength uint32
		requestID     uint32
		responseTo    uint32
		opCode        uint32
		flags         uint32
	}{
		length,
		0,
		0,
		OP_QUERY,
		0,
	}
	b := bytes.NewBuffer(make([]byte, 0))
	binary.Write(b, binary.LittleEndian, prologue)
	b.Write(cname)
	b.Write([]byte{0, 0, 0, 0}) // numberToSkip
	b.Write([]byte{0, 0, 0, 0}) // numberToReturn
	b.Write(serializedDoc)
	return b.Bytes()
}

func genReply(documents ...interface{}) []byte {
	serializedDocs := make([]byte, 0)
	for _, doc := range documents {
		s, _ := bson.Marshal(doc)
		serializedDocs = append(serializedDocs, s...)
	}
	length := uint32(36 + len(serializedDocs))
	prologue := struct {
		messageLength  uint32
		requestID      uint32
		responseTo     uint32
		opCode         uint32
		flags          uint32
		cursorID       uint64
		startingFrom   uint32
		numberReturned uint32
	}{
		length,
		0,
		0,
		OP_REPLY,
		0,
		0,
		0,
		uint32(len(documents)),
	}
	b := bytes.NewBuffer(make([]byte, 0))
	binary.Write(b, binary.LittleEndian, prologue)
	b.Write(serializedDocs)
	return b.Bytes()
}

func genOldStyleInsert(collectionName string, documents ...interface{}) []byte {
	serializedDocs := make([]byte, 0)
	for _, doc := range documents {
		s, _ := bson.Marshal(doc)
		serializedDocs = append(serializedDocs, s...)
	}
	cname := append([]byte(collectionName), '\x00')
	// Insert message consists of header (16 bytes), flags (4 bytes),
	// collection name and serialized documents.
	length := uint32(16 + 4 + len(cname) + len(serializedDocs))
	prologue := struct {
		MessageLength uint32
		RequestID     uint32
		ResponseTo    uint32
		OpCode        uint32
		flags         uint32
	}{
		length,
		0,
		0,
		OP_INSERT,
		0,
	}
	b := bytes.NewBuffer(make([]byte, 0))
	binary.Write(b, binary.LittleEndian, prologue)
	b.Write(cname)
	b.Write(serializedDocs)
	return b.Bytes()
}

// Implements sniffer.Message
type message struct {
	flow  sniffer.IPPortTuple
	ts    time.Time
	r     io.Reader
	bytes []byte
}

func (m *message) Flow() sniffer.IPPortTuple { return m.flow }
func (m *message) Timestamp() time.Time      { return m.ts }
func (m *message) Read(p []byte) (int, error) {
	return m.r.Read(p)
}

type messageStream struct {
	messages []*message
	index    int
}

func (ms *messageStream) Append(b []byte, ts time.Time, flow sniffer.IPPortTuple) {
	ms.messages = append(ms.messages, &message{
		r:    bytes.NewReader(b),
		flow: flow,
		ts:   ts,
	})
}

func (ms *messageStream) Next() (sniffer.Message, bool) {
	if ms.index < len(ms.messages) {
		m := ms.messages[ms.index]
		ms.index++
		return m, true
	} else {
		return nil, false
	}
}

func defaultFlow() sniffer.IPPortTuple {
	return sniffer.IPPortTuple{
		SrcIP:   net.IPv4(10, 0, 0, 22),
		DstIP:   net.IPv4(10, 0, 0, 23),
		SrcPort: 44444,
		DstPort: 27017,
	}
}

type testPublisher struct {
	output [][]byte
}

func (tp *testPublisher) Publish(m []byte) bool {
	tp.output = append(tp.output, m)
	return true
}

func newParser(publisher publish.Publisher) sniffer.Consumer {
	pf := ParserFactory{Options: Options{Port: 27017}, Publisher: publisher}
	return pf.New(defaultFlow())
}
