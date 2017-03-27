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
	"testing/iotest"
	"testing/quick"
	"time"

	"github.com/honeycombio/honeycomb-tcpagent/publish"
	"github.com/honeycombio/honeycomb-tcpagent/sniffer"
	"github.com/stretchr/testify/assert"

	"gopkg.in/mgo.v2/bson"
)

type request struct {
	requestID uint32
	query     string
}

type response struct {
	responseTo uint32
	replyDocs  []string
}

func TestParseQueries(t *testing.T) {
	ts := time.Date(2006, 1, 2, 15, 4, 5, 0, time.UTC)
	collectionName := "db.$cmd"
	var queryTests = []struct {
		request  request
		response response
		output   string
	}{
		{ // Basic insert query
			request{0, `{
				"find":   "collection0",
				"filter": {"rating": {"$gte": 9}, "cuisine": "italian"}
			}`},
			response{0, []string{`{ }`}},
			`{
				"command_type": "find",
				"command": "{\"filter\":{\"cuisine\":\"italian\",\"rating\":{\"$gte\":9}},\"find\":\"collection0\"}",
				"normalized_query": "{\"filter\":{\"cuisine\":1,\"rating\":{\"$gte\":1}},\"find\":1}",
				"nreturned": 1,
				"ninserted": 0,
				"namespace": "db.$cmd",
				"collection": "collection0",
				"database": "db",
				"request_length": 0,
				"response_length": 0,
				"duration_ms": 0,
				"server_ip": "10.0.0.23",
				"client_ip": "10.0.0.22",
				"request_id": 0,
				"request_length": 124,
				"response_length": 41
			}`,
		},
		{ // Basic getMore query
			request{0, `{
				"getMore": 0,
				"collection": "restaurant",
				"batchSize": 100,
				"maxTimeMS": 1000
			}`},
			response{0, []string{`{}`}},
			`{
				"command_type": "getMore",
				"command": "{\"batchSize\":100,\"collection\":\"restaurant\",\"getMore\":0,\"maxTimeMS\":1000}",
				"nreturned": 1,
				"ninserted": 0,
				"namespace": "db.$cmd",
				"normalized_query": "{\"batchSize\":1,\"collection\":1,\"getMore\":1,\"maxTimeMS\":1}",
				"collection": "restaurant",
				"database": "db",
				"request_length": 0,
				"response_length": 0,
				"duration_ms": 0,
				"server_ip": "10.0.0.23",
				"client_ip": "10.0.0.22",
				"request_id": 0,
				"request_length": 123,
				"response_length": 41
			}`,
		},
		{ // Long insert
			request{0, fmt.Sprintf(`{
				"insert":   "collection0",
				"documents": [{"key": "%s"}]
			}`, strings.Repeat("x", 2048))},
			response{0, []string{`{"ok": 1, "n": 1}`}},
			`{
				"command":"{\"documents\":[{\"key\":\"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx ...",
				"client_ip":"10.0.0.22",
				"collection":"collection0",
				"command_type":"insert",
				"database":"db",
				"duration_ms":0,
				"namespace":"db.$cmd",
				"normalized_query": "{\"documents\":[{\"key\":1}],\"insert\":1}",
				"ninserted":1,
				"nreturned":1,
				"request_id":0,
				"request_length":2147,
				"response_length":64,
				"server_ip":"10.0.0.23"
			}`,
		},
		{ // Response without matching request
			request{0, `{}`},
			response{1, []string{`{}`}},
			``,
		},
		{ // isMaster command
			request{0, `{"isMaster" :1}`},
			response{0, []string{`{}`}},
			`{
				"command": "{\"isMaster\":1}",
				"client_ip": "10.0.0.22",
				"collection": "$cmd",
				"command_type": "isMaster",
				"database": "db",
				"duration_ms": 0,
				"namespace": "db.$cmd",
				"ninserted": 0,
				"normalized_query": "{\"isMaster\":1}",
				"nreturned": 1,
				"request_id": 0,
				"request_length": 59,
				"response_length": 41,
				"server_ip": "10.0.0.23"
			}`,
		},
	}
	for _, testcase := range queryTests {
		tp := &testPublisher{}
		parser := newParser(tp)
		query, err := genQuery(collectionName, testcase.request)
		assert.Nil(t, err)
		reply, err := genReply(testcase.response)
		assert.Nil(t, err)
		ms := &messageStream{}
		ms.Append(query, ts, defaultFlow())
		ms.Append(reply, ts, defaultFlow().Reverse())
		parser.On(ms)
		if len(testcase.output) > 0 {
			assert.Equal(t, 1, len(tp.output))
			assert.JSONEq(t, string(tp.output[0]), testcase.output)
		} else {
			assert.Equal(t, 0, len(tp.output))
		}
	}
}

func TestCommandHashing(t *testing.T) {
	ts := time.Date(2006, 1, 2, 15, 4, 5, 0, time.UTC)
	collectionName := "db.$cmd"
	tp := &testPublisher{}
	pf := ParserFactory{
		Options:   Options{Port: 27017, ScrubCommand: true},
		Publisher: tp,
	}
	parser := pf.New(defaultFlow())
	request := request{0, `{
				"find":   "collection0",
				"filter": {"rating": {"$gte": 9}, "cuisine": "italian"}
			}`}
	response := response{0, []string{`{ }`}}
	query, err := genQuery(collectionName, request)
	assert.Nil(t, err)
	reply, err := genReply(response)
	assert.Nil(t, err)
	ms := &messageStream{}
	ms.Append(query, ts, defaultFlow())
	ms.Append(reply, ts, defaultFlow().Reverse())
	parser.On(ms)
	assert.Equal(t, 1, len(tp.output))
	var out map[string]interface{}
	err = json.Unmarshal(tp.output[0], &out)
	assert.Nil(t, err)
	assert.Equal(t, out["command"],
		"d37492dcfdb60a87dfe55da2bdba09fb5675d4b5439e9d74e65ff36ed5e4f091")
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
	assert.Equal(t, ret["command_type"], "insert")
	assert.Equal(t, ret["ninserted"], float64(1))
	assert.Equal(t, ret["client_ip"], "10.0.0.22")
	assert.Equal(t, ret["server_ip"], "10.0.0.23")
	assert.Equal(t, ret["collection"], "collection0")
	assert.Equal(t, ret["database"], "db")
	assert.Equal(t, ret["namespace"], "db.collection0")
}

func TestRemainingBytesDiscardedOnError(t *testing.T) {
	f := func(b []byte) bool {
		tp := &testPublisher{}
		parser := newParser(tp)
		ms := &messageStream{}
		m := message{
			ts:   defaultDate(),
			flow: defaultFlow(),
			r:    bytes.NewReader(b),
		}
		ms.messages = append(ms.messages, &m)
		parser.On(ms)
		discardBuffer := make([]byte, 1)
		n, err := m.Read(discardBuffer)
		if err != io.EOF || n > 1 {
			return false
		}
		return true
	}
	if err := quick.Check(f, nil); err != nil {
		t.Error("Not all bytes read from input", err)
	}
}

func TestReadRawMsg(t *testing.T) {
	q, err := genQuery("collection", request{0, `{"isMaster" :1}`})
	assert.Nil(t, err)
	r := iotest.DataErrReader(bytes.NewReader(q))
	_, _, err = readRawMsg(r)
	assert.Nil(t, err)
}

func genQuery(collectionName string, request request) ([]byte, error) {
	var document map[string]interface{}
	err := json.Unmarshal([]byte(request.query), &document)
	if err != nil {
		return nil, err
	}
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
		request.requestID,
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
	return b.Bytes(), nil
}

func genReply(response response) ([]byte, error) {
	var serializedDocs []byte
	for _, rawDoc := range response.replyDocs {
		var doc map[string]interface{}
		err := json.Unmarshal([]byte(rawDoc), &doc)
		if err != nil {
			return nil, err
		}
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
		response.responseTo,
		OP_REPLY,
		0,
		0,
		0,
		uint32(len(response.replyDocs)),
	}
	b := bytes.NewBuffer(make([]byte, 0))
	binary.Write(b, binary.LittleEndian, prologue)
	b.Write(serializedDocs)
	return b.Bytes(), nil
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
	flow sniffer.IPPortTuple
	ts   time.Time
	r    io.Reader
}

func (m *message) Flow() sniffer.IPPortTuple { return m.flow }
func (m *message) Timestamp() time.Time      { return m.ts }
func (m *message) Read(p []byte) (int, error) {
	return m.r.Read(p)
}

type messageStream struct {
	messages []sniffer.Message
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

func defaultDate() time.Time {
	return time.Date(2006, 1, 2, 15, 4, 5, 0, time.UTC)
}

type testPublisher struct {
	output [][]byte
}

func (tp *testPublisher) Publish(data interface{}, timestamp time.Time) {
	m, _ := json.Marshal(data)
	tp.output = append(tp.output, m)
}

func newParser(publisher publish.Publisher) sniffer.Consumer {
	pf := ParserFactory{Options: Options{Port: 27017}, Publisher: publisher}
	return pf.New(defaultFlow())
}
