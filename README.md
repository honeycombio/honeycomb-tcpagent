(Under development)

Honeypacket captures database network traffic and writes it as structured JSON
to stdout, enabling query-level visibility with low overhead.


## Quickstart For Go users


```
sudo apt-get install -y libpcap0.8 libpcap0.8-dev
go get github.com/honeycombio/honeypacket
sudo setcap cap_net_raw=eip $GOPATH/bin/honeypacket
```

Then run `honeypacket` to start capturing traffic.
