# samples

`sample-mixed.pcap` is a 23-packet synthetic capture that opens in Wireshark/tshark, in `pcapreplay stats`, and in the GUI:

| Conversation | Packets |
|---|---|
| ARP request/reply | 2 |
| DNS query/response (UDP 40000 -> 53) | 2 |
| HTTP GET / 200 over TCP with handshake and FIN (51234 -> 80) | 10 |
| ICMP echo (3 pings) | 6 |
| UDP syslog to port 514 (three flows) | 3 |

Regenerate it with `go run ./cmd/pcapgen -sample -o samples/sample-mixed.pcap`. It contains no real traffic.

```bash
pcapreplay stats samples/sample-mixed.pcap
pcapreplay conversations samples/sample-mixed.pcap
pcapreplay replay -mode tcp -backend null -burst samples/sample-mixed.pcap   # picks the HTTP flow
```
