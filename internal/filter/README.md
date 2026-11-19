# internal/filter

Compiles a boolean filter expression into a tree of **closures** that run directly on a raw frame and its pre-decoded
`decode.Info`.

```go
f, err := filter.Parse(`src_ip == 10.0.0.0/8 AND (dst_port in 8000-8100 OR payload contains "POST ")`)
if f.MatchAll() { ... }                    // an empty expression: skip the call entirely
ok := f.Match(frame, &info)
```

## Language

| Term | Meaning |
|---|---|
| `src_ip`, `dst_ip`, `ip` `== ADDR[/CIDR]` | Address tests (IPv4 and IPv6); `ip` matches either side. |
| `src_port`, `dst_port`, `port` `== N` / `in LO-HI` | Port tests. |
| `proto == tcp\|udp\|icmp\|icmp6\|arp\|ip\|ipv6\|N` | Protocol. |
| `tcp_flags == syn+ack` | TCP flag sets joined with `+`. |
| `payload contains "text"` / `0xHEX` / `payload ~ "regexp"` | Payload tests (Go RE2 regular expressions). |
| `!=`, `AND`/`&&`, `OR`/`||`, `NOT`/`!`, parentheses | Combinators. |

The complete reference with examples is in [README-CLI.md](../../README-CLI.md#filter-expressions).

## How it works

1. `lex` turns the text into tokens; a recursive-descent parser (`or` → `and` → `unary` → `cmp`) builds `node`s.
2. Each comparison becomes a small closure specialised for its field (`ipNode`, `portNode`, `protoNode`, `flagsNode`,
   `payloadNode`), with prefixes, ranges and regular expressions **compiled once** at parse time.
3. `combine` **orders the children of every AND/OR by cost**: header tests (cheap, constant time) run before payload
   tests (`bytes.Contains`, regexp). So `payload contains "x" AND dst_port == 80` rejects on the port before scanning
   a single payload byte, whatever order the user typed. A header-only evaluation costs about 28 ns with no allocation.

Parse errors are reported with the offending token before any packet is processed.

## Tests

`filter_test.go` checks parsing, precedence, every field, cost ordering and error messages; a benchmark tracks the
header-only fast path.

Used by: `stats`, `replay`, `gui` (live filter validation), `cmd/pktreplay`.
