[![Build Status](https://travis-ci.org/honeycombio/honeypacket.svg?branch=master)](https://travis-ci.org/honeycombio/honeypacket)

Honeypacket captures database network traffic and writes it as structured JSON to stdout, enabling query-level visibility with low overhead. Currently, MongoDB is supported and MySQL is under development. [Get in touch](https://honeycomb.io/help/) if you'd like support for something else!


## Quickstart For Go users


```
sudo apt-get install -y libpcap0.8-dev
go get github.com/honeycombio/honeypacket
sudo setcap cap_net_raw=eip $GOPATH/bin/honeypacket
```

Then run `honeypacket` to start capturing traffic.
