package publish

import (
	"github.com/Sirupsen/logrus"
	"github.com/codahale/metrics"
	libhoney "github.com/honeycombio/libhoney-go"
)

type Publisher interface {
	Publish(data interface{})
}

// BufferedPublisher buffers serialized events before sending them to stdout.
// It /drops/ additional events if the channel buffer becomes full.
// If ingestion can't keep up with TCP traffic, it's better to drop events than
// packets.
type BufferedPublisher struct{}

func NewBufferedPublisher(config libhoney.Config) *BufferedPublisher {
	libhoney.Init(config)

	bp := &BufferedPublisher{}
	go bp.Run()
	return bp
}

func (bp *BufferedPublisher) Run() {
	for r := range libhoney.Responses() {
		if r.Err != nil && r.Err.Error() == "queue overflow" {
			metrics.Counter("publish.events_dropped").Add()
		} else if r.Err != nil {
			logrus.WithError(r.Err).Warning("Error publishing event")
			metrics.Counter("publish.event_errors").Add()
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

func (bp *BufferedPublisher) Publish(data interface{}) {
	ev := libhoney.NewEvent()
	ev.Add(data) // TODO: check errors
	ev.Send()
}
