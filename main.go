package main

import (
	"errors"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/Sirupsen/logrus"
	"github.com/codahale/metrics"
	"github.com/honeycombio/honeycomb-tcpagent/protocols/mongodb"
	"github.com/honeycombio/honeycomb-tcpagent/protocols/mysql"
	"github.com/honeycombio/honeycomb-tcpagent/publish"
	"github.com/honeycombio/honeycomb-tcpagent/sniffer"
	libhoney "github.com/honeycombio/libhoney-go"

	flag "github.com/jessevdk/go-flags"
)

type RequiredOptions struct {
	WriteKey string `long:"writekey" short:"k" description:"Team write key"`
	Dataset  string `long:"dataset" short:"d" description:"Name of the dataset"`
}

type GlobalOptions struct {
	Help               bool            `short:"h" long:"help" description:"Show this help message"`
	Debug              bool            `long:"debug" description:"Print verbose debug logs"`
	Required           RequiredOptions `group:"Required options"`
	ConfigFile         string          `short:"c" long:"config" description:"Config file for honeycomb-tcpagent in INI format." no-ini:"true"`
	APIHost            string          `long:"api_host" description:"Hostname for the Honeycomb API server" default:"https://api.honeycomb.io/"`
	SampleRate         uint            `long:"samplerate" short:"r" description:"Only send 1 / rate events" default:"1"`
	MySQL              mysql.Options   `group:"MySQL parser options" namespace:"mysql"`
	MongoDB            mongodb.Options `group:"MongoDB parser options" namespace:"mongodb"`
	Sniffer            sniffer.Options `group:"Packet capture options" namespace:"capture"`
	ParserName         string          `short:"p" long:"parser" default:"mongodb" description:"Which protocol to parse (MySQL or MongoDB)"` // TODO: just support both!
	StatusInterval     int             `long:"status_interval" default:"60" description:"How frequently to print summary statistics, in seconds"`
	WriteDefaultConfig bool            `long:"write_default_config" description:"Write a default config file to STDOUT" no-ini:"true"`
}

func main() {
	options, err := parseFlags()
	if err != nil {
		log.Println("Error parsing options:", err)
		os.Exit(1)
	}
	configureLogging(options.Debug)
	go logMetrics(options.StatusInterval)
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

	libhoneyOptions := libhoney.Config{
		WriteKey:   options.Required.WriteKey,
		Dataset:    options.Required.Dataset,
		APIHost:    options.APIHost,
		SampleRate: options.SampleRate,
	}

	if options.ParserName == "mysql" {
		pf = &mysql.ParserFactory{Options: options.MySQL}
	} else if options.ParserName == "mongodb" {
		pf = &mongodb.ParserFactory{
			Options:   options.MongoDB,
			Publisher: publish.NewBufferedPublisher(libhoneyOptions),
		}
	} else {
		log.Printf("`%s` isn't a supported parser name.\n", options.ParserName)
		log.Println("Valid parsers are `mongodb` and `mysql`.")
		os.Exit(1)
	}

	sniffer, err := sniffer.New(options.Sniffer, pf)
	if err != nil {
		log.Println("Failed to configure listener.")
		log.Printf("Error: %s\n", err)
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
			return nil, err
		}
	} else if len(extraArgs) != 0 {
		log.Printf("Unexpected extra arguments: %s\n", strings.Join(extraArgs, " "))
		return nil, errors.New("")
	}

	if options.WriteDefaultConfig {
		ip := flag.NewIniParser(flagParser)
		ip.Write(os.Stdout, flag.IniIncludeDefaults|flag.IniCommentDefaults|flag.IniIncludeComments)
		os.Exit(0)
	}

	if options.ConfigFile != "" {
		ini := flag.NewIniParser(flagParser)
		ini.ParseAsDefaults = true
		if err := ini.ParseFile(options.ConfigFile); err != nil {
			fmt.Printf("Error: failed to parse config file %s\n", options.ConfigFile)
			return nil, err
		}
	}

	if options.Required.WriteKey == "" {
		var opt string
		if options.ConfigFile != "" {
			opt = "WriteKey"
		} else {
			opt = "-k/--writekey"
		}
		return nil, fmt.Errorf("Missing required write key option %v", opt)
	}
	if options.Required.Dataset == "" {
		var opt string
		if options.ConfigFile != "" {
			opt = "Dataset"
		} else {
			opt = "-d/--dataset"
		}
		return nil, fmt.Errorf("Missing required dataset option %v", opt)
	}

	return &options, nil
}

func logMetrics(interval int) {
	ticker := time.NewTicker(time.Second * time.Duration(interval))
	for range ticker.C {
		counters, gauges := metrics.Snapshot()
		logger := logrus.WithFields(logrus.Fields{})
		for k, v := range counters {
			logger = logger.WithField(k, v)
		}
		for k, v := range gauges {
			logger = logger.WithField(k, v)
		}
		logger.Info("honeycomb-tcpagent statistics")
	}
}
