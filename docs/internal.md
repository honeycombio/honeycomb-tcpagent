## Notes on honeycomb-tcpagent internals
(2017-04-24)

Honeycomb-tcpagent uses https://github.com/google/gopacket, a wrapper around
libpcap, to parse TCP traffic. Code in `sniffer/sniffer.go` is responsible for
instantiating a packet capture handle and decoding packets.
`sniffer/tcpassembly.go` contains code for reassembling individual TCP streams,
and handing their data off to consumers:

```
                                                   +-> Stream.ReassembledSG
                                                   |
                                                   |
sniffer.Run() --> assembler.AssembleWithContext ---+-> Stream.ReassembledSG
                                                   |
                                                   |
                                                   +-> Stream.ReassembledSG
```

For each bidirectional TCP stream (i.e., each connection between a specific
server and client), the assembler instantiates a `Stream` struct.
`Stream.ReassembledSG` receives sequences of reassembled packets in order,
together with some metadata. It puts these into `Message` objects. A `Message`
encapsulates a concatenated sequence of consecutive TCP segments in the same
direction -- in other words, in a typical request/response oriented protocol,
each request/response is a single `Message`.

`Message`s are sent along a channel to a consumer (a protocol-specific parser),
which decodes them into e.g. MongoDB queries and responses. The consumer turns
these into structured objects, before sending those to a publisher. Usually,
this is the `HoneycombPublisher`, which sends events to the Honeycomb API.

One consumer is instantiated per `Stream` (using the `ConsumerFactory`
interface).


### MySQL-specific TODOs
There's a partial implementation of a MySQL protocol parser with a variety of
unfinished parts:
- Needs unit tests.
- Doesn't parse contents of OK/EOF/ERR packets -- these can contain useful
  information, such as error codes.
- Doesn't parse non-QUERY packets sent from the client to the server.
- Doesn't do any query normalization.
- It doesn't properly handle empty result sets (i.e., queries that return no
  rows).
- It may not properly handle huge result sets that span multiple *MySQL*
  packets (not TCP packets).


### Miscellaneous notes
- Packet captures can and will drop packets! It's important to handle that
  case. Especially for MySQL, where you can't reassociate queries and responses
  using a unique ID, that means that you probable need to drop the stream if
  any packets are skipped.

- Currently, the code uses a fork of gopacket at
  https://github.com/emfree/gopacket, in order to use the new reassembly API as
  well as BPF filters on `af_packet` handles. Since original work on this
  project, those features have been merged into mainline gopacket. So the code
  could (should) be switched to use upstream. We should also really be
  vendoring dependencies.
