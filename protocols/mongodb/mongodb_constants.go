package mongodb

import (
	"bytes"
	"encoding/binary"
	"errors"

	"gopkg.in/mgo.v2/bson"
)

// See https://docs.mongodb.com/manual/reference/mongodb-wire-protocol/

const (
	OP_REPLY        = 1
	OP_MSG          = 1000
	OP_UPDATE       = 2001
	OP_INSERT       = 2002
	RESERVED        = 2003
	OP_QUERY        = 2004
	OP_GET_MORE     = 2005
	OP_DELETE       = 2006
	OP_KILL_CURSORS = 2007
	OP_COMMAND      = 2010
	OP_COMMANDREPLY = 2011
)

type opType string

const (
	Find          opType = "find"
	Insert               = "insert"
	Update               = "update"
	Delete               = "delete"
	GetMore              = "getMore"
	FindAndModify        = "findAndModify"
	Count                = "count"
)

type document bson.M
type cstring []byte

type updateMsg struct {
	ZERO               int32    // 0 - reserved for future use
	FullCollectionName cstring  // "dbname.collectionname"
	Flags              int32    // bit vector. see below
	Selector           document // the query to select the document
	Update             document // specification of the update to perform
}

func readUpdateMsg(data []byte) (*updateMsg, error) {
	r := newErrReader(data)
	m := updateMsg{}

	m.ZERO = r.Int32()
	m.FullCollectionName = r.CString()
	m.Flags = r.Int32()
	m.Selector = r.Document()
	m.Update = r.Document()
	if r.err != nil {
		return nil, r.err
	}
	return &m, nil

}

type insertMsg struct {
	Flags              int32   // bit vector - see below
	FullCollectionName cstring // "dbname.collectionname"
	// Documents       []document
	// ^ not parsed. Instead we compute NInserted:
	NInserted int
}

func readInsertMsg(data []byte) (*insertMsg, error) {
	r := newErrReader(data)
	m := insertMsg{}
	m.Flags = r.Int32()
	m.FullCollectionName = r.CString()
	m.NInserted = r.DocumentArrayLength()
	if r.err != nil {
		return nil, r.err
	}
	return &m, nil
}

type queryMsg struct {
	Flags                int32    // bit vector of query options.
	FullCollectionName   cstring  // "dbname.collectionname"
	NumberToSkip         int32    // number of documents to skip
	NumberToReturn       int32    // number of documents to return in the first OP_REPLY batch
	Query                document // query object.
	ReturnFieldsSelector document // Optional. Selector indicating the fields to return.
}

func readQueryMsg(data []byte) (*queryMsg, error) {
	r := newErrReader(data)
	m := queryMsg{}
	m.Flags = r.Int32()
	m.FullCollectionName = r.CString()
	m.NumberToSkip = r.Int32()
	m.NumberToReturn = r.Int32()
	m.Query = r.Document()
	if r.err != nil {
		return nil, r.err
	}

	// TODO: what's up with this ReturnFieldsSelector thing?
	return &m, nil
}

type getMoreMsg struct {
	ZERO               int32   //0 - reserved for future use
	FullCollectionName cstring //"dbname.collectionname"
	NumberToReturn     int32   //number of documents to return
	CursorID           int64   //cursorID from the OP_REPLY
}

func readGetMoreMsg(data []byte) (*getMoreMsg, error) {
	r := newErrReader(data)
	m := getMoreMsg{}
	m.ZERO = r.Int32()
	m.FullCollectionName = r.CString()
	m.NumberToReturn = r.Int32()
	m.CursorID = r.Int64()
	if r.err != nil {
		return nil, r.err
	}

	return &m, nil
}

type deleteMsg struct {
	ZERO               int32    //0 - reserved for future use
	FullCollectionName cstring  //"dbname.collectionname"
	Flags              int32    //bit vector
	Selector           document //query object.
}

func readDeleteMsg(data []byte) (*deleteMsg, error) {
	r := newErrReader(data)
	m := deleteMsg{}
	m.ZERO = r.Int32()
	m.FullCollectionName = r.CString()
	m.Flags = r.Int32()
	m.Selector = r.Document()
	if r.err != nil {
		return nil, r.err
	}
	return &m, nil
}

type killCursorsMsg struct {
	ZERO              int32   // 0 - reserved for future use
	NumberOfCursorIDs int32   // number of cursorIDs in message
	CursorIDs         []int64 // sequence of cursorIDs to close
}

type replyMsg struct {
	ResponseFlags  int32 // bit vector
	CursorID       int64 // cursor id if client needs to do get more's
	StartingFrom   int32 // where in the cursor this reply is starting
	NumberReturned int32 // number of documents in the reply
	//Documents      []document // documents
}

func readReplyMsg(data []byte) (*replyMsg, error) {
	r := newErrReader(data)
	m := replyMsg{}
	m.ResponseFlags = r.Int32()
	m.CursorID = r.Int64()
	m.StartingFrom = r.Int32()
	m.NumberReturned = r.Int32()
	if r.err != nil {
		return nil, r.err
	}

	return &m, nil
}

// TODO: do we need to worry about OP_MSG, OP_COMMAND, OP_COMMAND_REPLY?

// errReader wraps a buffer with convenience functions for parsing MongoDB datatypes.
// Instead of returning error values, errReader methods check errReader.err,
// and store any errors they encounter. This eliminates a lot of `if err != nil`
// boilerplate. But callers *must* check errReader.err before returning.
type errReader struct {
	err error
	b   *bytes.Buffer
}

func newErrReader(data []byte) *errReader {
	return &errReader{b: bytes.NewBuffer(data)}
}

func (e *errReader) Document() document {
	if e.err != nil {
		return nil
	}
	var length uint32
	e.err = binary.Read(e.b, binary.LittleEndian, &length)
	if e.err != nil {
		return nil
	}
	var buf []byte
	buf, e.err = newSafeBuffer(int(length))
	if e.err != nil {
		return nil
	}

	binary.LittleEndian.PutUint32(buf[:4], length)
	_, e.err = e.b.Read(buf[4:])
	if e.err != nil {
		return nil
	}

	m := bson.M{}
	e.err = bson.Unmarshal(buf, m)
	if e.err != nil {
		return nil
	}
	return document(m)
}

func (e *errReader) DocumentArrayLength() int {
	// Don't try to decode the document contents for now, just figure out how
	// many of them there are.
	if e.err != nil {
		return 0
	}
	n := 0
	for e.b.Len() > 0 {
		var docLength uint32
		e.err = binary.Read(e.b, binary.LittleEndian, &docLength)
		if e.err != nil {
			return 0
		}

		// Length of the remainder of the document in bytes
		innerLength := docLength - 4

		if int(innerLength) > e.b.Len() {
			// TODO: better error typing
			e.err = errors.New("DocumentArrayLength out-of-bound read")
			return 0
		}
		e.b.Next(int(innerLength))
		n++
	}
	return n
}

func (e *errReader) CString() cstring {
	if e.err != nil {
		return nil
	}

	var ret cstring
	ret, e.err = e.b.ReadBytes(0x00)
	if e.err != nil {
		return nil
	}
	return ret[:len(ret)-1]
}

func (e *errReader) Int32() int32 {
	if e.err != nil {
		return 0
	}
	var v int32
	e.err = binary.Read(e.b, binary.LittleEndian, &v)
	return v
}

func (e *errReader) Int64() int64 {
	if e.err != nil {
		return 0
	}
	var v int64
	e.err = binary.Read(e.b, binary.LittleEndian, &v)
	return v
}
