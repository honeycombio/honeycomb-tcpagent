package mongodb

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"testing"
	"time"

	"github.com/honeycombio/honeypacket/sniffer"
	"github.com/stretchr/testify/assert"

	"gopkg.in/mgo.v2/bson"
)

func genInsert(collectionName []byte, documents ...interface{}) []byte {
	serializedDocs := make([]byte, 0)
	for _, doc := range documents {
		s, _ := bson.Marshal(doc)
		serializedDocs = append(serializedDocs, s...)
	}
	collectionName = append(collectionName, '\x00')
	// Insert message consists of header (16 bytes), flags (4 bytes),
	// collection name and serialized documents.
	length := uint32(16 + 4 + len(collectionName) + len(serializedDocs))
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
	b.Write(collectionName)
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

func TestParseInsert(t *testing.T) {
	var results [][]byte
	send := func(event []byte) {
		results = append(results, event)
	}

	pf := ParserFactory{Options: Options{Port: 27017}, SendFunc: send}
	p := pf.New(defaultFlow())
	// TODO: better injection of test message data
	collectionName := []byte("collection0")
	doc := map[string]interface{}{
		"a": "b",
	}
	insert := genInsert(collectionName, doc)
	ts := time.Now()
	m := message{
		flow: defaultFlow(),
		ts:   ts,
		r:    bytes.NewReader(insert),
	}
	ms := &messageStream{
		messages: []*message{&m},
	}
	p.On(ms)
	assert.Equal(t, len(results), 1)
	var ret map[string]interface{}
	json.Unmarshal(results[0], &ret)
	assert.Equal(t, ret["OpType"], "insert")
	assert.Equal(t, ret["NInserted"], float64(1))
	assert.Equal(t, ret["ClientIP"], "10.0.0.22")
	assert.Equal(t, ret["ServerIP"], "10.0.0.23")
	assert.Equal(t, ret["Collection"], "collection0")
	// TODO
	//assert.Equal(t, ret["Timestamp"], ts)
}
