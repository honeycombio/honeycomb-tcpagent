package main

import (
	"errors"
	"log"
	"os"
	"strings"

	"github.com/Sirupsen/logrus"
	"github.com/honeycombio/honeypacket/protocols/mongodb"
	"github.com/honeycombio/honeypacket/protocols/mysql"
	"github.com/honeycombio/honeypacket/sniffer"

	flag "github.com/jessevdk/go-flags"
)

type GlobalOptions struct {
	Help             bool            `short:"h" long:"help" description:"Show this help message"`
	NetworkInterface string          `short:"i" long:"interface" description:"Network interface to listen on"`
	BufSizeMb        int             `long:"bufsize" description:"AF_PACKET buffer size in megabytes" default:"30"`
	SnapLen          int             `long:"snaplen" default:"65535"`
	Debug            bool            `long:"debug"`
	MySQL            mysql.Options   `group:"MySQL parser options" namespace:"mysql"`
	MongoDB          mongodb.Options `group:"mongodb parser options" namespace:"mongodb"`
	ParserName       string          `short:"p" long:"parser" description:"Which protocol to parse (MySQL or MongoDB)"` // TODO: just support both!
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

func run(options *GlobalOptions) error {
	var pf sniffer.ConsumerFactory
	if options.ParserName == "mysql" {
		pf = &mysql.ParserFactory{Options: options.MySQL}
	} else if options.ParserName == "mongodb" {
		pf = &mongodb.ParserFactory{Options: options.MongoDB}
	} else {
		// TODO: this should be better
		log.Println("Invalid parser name")
		os.Exit(1)
	}
	sniffer, err := sniffer.New(options.NetworkInterface, options.BufSizeMb, options.SnapLen, pf)
	if err != nil {
		log.Println("Failed to configure sniffer:")
		log.Printf("\t%s\n", err)
		return err
	}
	log.Println("Listening for traffic")
	sniffer.Run()
	return nil
}

func parseFlags() (*GlobalOptions, error) {
	var options GlobalOptions
	flagParser := flag.NewParser(&options, flag.Default)
	extraArgs, err := flagParser.Parse()

	if err != nil {
		if flagErr, ok := err.(*flag.Error); ok && flagErr.Type == flag.ErrHelp {
			os.Exit(0)
		} else {
			os.Exit(1)
		}
	} else if len(extraArgs) != 0 {
		log.Printf("Unexpected extra arguments: %s", strings.Join(extraArgs, " "))
		return nil, errors.New("")
	}

	return &options, nil
}
