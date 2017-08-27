package publish

import (
	"bufio"
	"encoding/json"
	"os"
	"time"

	"github.com/Sirupsen/logrus"
	"github.com/codahale/metrics"
	libhoney "github.com/honeycombio/libhoney-go"
)

type Publisher interface {
	Publish(interface{}, time.Time)
}

type HoneycombPublisher struct{}

func NewHoneycombPublisher(config libhoney.Config) *HoneycombPublisher {
	libhoney.Init(config)

	hp := &HoneycombPublisher{}
	go hp.Run()
	return hp
}

func (hp *HoneycombPublisher) Run() {
	for r := range libhoney.Responses() {
		if r.Err != nil {
			if r.Err.Error() == "queue overflow" {
				metrics.Counter("publish.events_dropped").Add()
			} else if r.Err.Error() == "event dropped due to sampling" {
				metrics.Counter("publish.events_sampled_out").Add()
			} else {
				logrus.WithError(r.Err).Warning("Error publishing event")
				metrics.Counter("publish.event_errors").Add()
			}
		} else if r.StatusCode != 200 {
			logrus.WithFields(logrus.Fields{
				"http_status": r.StatusCode,
				"body":        string(r.Body)}).Warning(
				"HTTP error publishing event")
			metrics.Counter("publish.event_http_errors").Add()
		} else {
			metrics.Counter("publish.events_published").Add()
		}
	}
}

func (hp *HoneycombPublisher) Publish(data interface{}, timestamp time.Time) {
	ev := libhoney.NewEvent()
	ev.Add(data)
	ev.Timestamp = timestamp
	ev.Send()
}

// BufferedStdoutPublisher buffers serialized events before sending them to stdout.
// It /drops/ additional events if the channel buffer becomes full.
// If ingestion can't keep up with TCP traffic, it's better to drop events than
// packets.
type BufferedStdoutPublisher struct {
	buf chan []byte
	w   *bufio.Writer
}

func NewBufferedStdoutPublisher(bufsize int) *BufferedStdoutPublisher {
	bp := &BufferedStdoutPublisher{
		buf: make(chan []byte, bufsize),
		w:   bufio.NewWriter(os.Stdout),
	}
	go bp.Run()
	return bp
}

func (bp *BufferedStdoutPublisher) Run() {
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

func (bp *BufferedStdoutPublisher) Publish(data interface{}, timestamp time.Time) {
	m, err := json.Marshal(data)
	if err != nil {
		logrus.WithError(err).Error("Error marshaling query event")
		return
	}
	select {
	case bp.buf <- m:
	default:
	}
}
