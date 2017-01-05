
Honeypacket is a network traffic analysis tool designed to capture database
traffic.

## Development

1. Install [Go](https://golang.org/doc/install)

2. Install libpcap and libpcap headers:
    ```
    sudo apt-get install -y libpcap0.8 libpcap0.8-dev
    ```

3. Build the project
    ```
    go build
    ```

4. You'll need to run `honeypacket` as root, or give it CAP_NET_RAW capability:
    ```
    sudo setcap cap_net_raw=eip ./honeypacket
    ```

5. Start capturing traffic
    ```
    ./honeytail
    ```

