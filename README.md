[![Build Status](https://travis-ci.org/honeycombio/honeycomb-tcpagent.svg?branch=master)](https://travis-ci.org/honeycombio/honeycomb-tcpagent)

`honeycomb-tcpagent` captures database network traffic and forwards it to [Honeycomb](https://honeycomb.io), enabling query-level visibility with low overhead. Currently, MongoDB is supported and MySQL is under development. [Get in touch](https://honeycomb.io/help/) if you'd like support for something else!

[See the documentation](https://honeycomb.io/docs/mongodb/tcp) for instructions on using `honeycomb-tcpagent` to send data to [Honeycomb](https://honeycomb.io).


## Development instructions


```
sudo apt-get install -y libpcap0.8-dev
go get github.com/honeycombio/honeycomb-tcpagent
sudo setcap cap_net_raw=eip $GOPATH/bin/honeycomb-tcpagent
```

Then run `honeycomb-tcpagent` to start capturing traffic.

See docs/internal.md for some implementation notes.
