package main

import (
	"errors"
	"log"
	"os"
	"strings"
	"time"

	"github.com/Sirupsen/logrus"
	"github.com/honeycombio/honeypacket/protocols/mysql"
	"github.com/honeycombio/honeypacket/sniffer"

	flag "github.com/jessevdk/go-flags"
)

type options struct {
	Port             uint16 `short:"p" long:"port" description:"Port to listen on"`
	NetworkInterface string `short:"i" long:"interface" description:"Network interface to listen on"`
	PcapTimeoutMs    int64  `long:"timeout" description:"Pcap timeout in milliseconds" default:"1000"`
	BufSizeMb        int    `long:"bufsize" description:"AF_PACKET buffer size in megabytes" default:"30"`
	SnapLen          int    `long:"snaplen" default:"65535"`
	Debug            bool   `long:"debug"`
}

func main() {
	options, err := parseFlags()
	if err != nil {
		os.Exit(1)
	}
	configureLogging(options.Debug)
	err = run(options)
	if err != nil {
		os.Exit(1)
	}
}

func configureLogging(debug bool) {
	if debug {
		logrus.SetLevel(logrus.DebugLevel)
	}
	logrus.SetFormatter(&logrus.JSONFormatter{})
}

func run(options *options) error {
	pollTimeout := time.Duration(options.PcapTimeoutMs) * time.Millisecond
	mysqlConsumer := mysql.NewConsumer()
	sniffer, err := sniffer.New(options.NetworkInterface, options.BufSizeMb, options.SnapLen, pollTimeout, mysqlConsumer)
	if err != nil {
		log.Println("Failed to configure sniffer:")
		log.Printf("\t%s\n", err)
		return err
	}
	sniffer.SetBPFFilter("tcp port 3306") // debug
	sniffer.Run()
	return nil
}

func parseFlags() (*options, error) {
	var options options
	flagParser := flag.NewParser(&options, flag.Default)
	extraArgs, err := flagParser.Parse()
	if err != nil {
		log.Println("Failed to parse options:")
		log.Printf("\t%s\n", err)
		return nil, err
	} else if len(extraArgs) != 0 {
		log.Printf("Unexpected extra arguments: %s", strings.Join(extraArgs, " "))
		return nil, errors.New("")
	}

	return &options, nil
}
