package publish

import (
	"bufio"
	"os"
	"time"

	"github.com/codahale/metrics"
)

type Publisher interface {
	Publish(m []byte) bool
}

// BufferedPublisher buffers serialized events before sending them to stdout.
// It /drops/ additional events if the channel buffer becomes full.
// If ingestion can't keep up with TCP traffic, it's better to drop events than
// packets.
type BufferedPublisher struct {
	buf chan []byte
	w   *bufio.Writer
}

func NewBufferedPublisher(bufsize int) *BufferedPublisher {
	bp := &BufferedPublisher{
		buf: make(chan []byte, bufsize),
		w:   bufio.NewWriter(os.Stdout),
	}
	go bp.Run()
	return bp
}

func (bp *BufferedPublisher) Run() {
	t := time.Tick(time.Second)
	for {
		select {
		case m := <-bp.buf:
			bp.w.Write(m)
			bp.w.Write([]byte("\n"))
			metrics.Counter("publish.events_published").Add()
			// This'll be wrong if there are multiple BufferedPublishers running
			// concurrently. But we don't do that so it doesn't matter.
			metrics.Gauge("publish.buffer_depth").Set(int64(len(bp.buf)))
		case <-t:
			bp.w.Flush()
		}
	}
}

func (bp *BufferedPublisher) Publish(m []byte) bool {
	select {
	case bp.buf <- m:
		return true
	default:
		return false
	}
}
