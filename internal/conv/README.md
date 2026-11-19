# internal/conv

Groups packets into **bidirectional conversations**, names them with **selectors**, and defines per-conversation
**rewrite rules**.

## Concepts

* **Key**: `(protocol, {endpoint A, endpoint B})` with the endpoints in canonical order, so both directions of an
  exchange share one key (ICMP uses port 0). `MakeKey`, `KeyOf(*decode.Info)`.
* **Table**: tracks conversations with bounded memory (default 100 000). Packets of conversations beyond the cap are
  counted in `Untracked`. Each `Conversation` has packet/byte counts per direction, first/last timestamp, TCP state,
  and the detected client and server.
* **Roles**: the client is the SYN sender; a SYN-ACK identifies the server; for mid-stream captures a well-known port
  (< 1024) against an ephemeral one marks the server; a SYN seen later corrects a wrong guess and swaps the
  direction counters.
* **Selector**: `proto/client/server`, e.g. `tcp/192.168.1.50:51234/192.168.1.10:80` (`[v6]:port` for IPv6, bare
  addresses for ICMP). `Selector(...)` formats it, `ParseSelector` reads it. The same syntax is used by the CLI
  (`-conv`) and the GUI.
* **Rule** (`Rule`, `ParseRule`): `SELECTOR[,client-ip=..][,client-port=..][,server-ip=..][,server-port=..][,replace=a=>b]`.
  `Rule.Rewrites()` returns the packet-level rewrites for each direction.
* **Set** (`NewSet`): validated, indexed rules with `Lookup(*decode.Info)` and `ForKey`.

## How a rule becomes packet rewrites

A rule speaks in *endpoints*. "The server is now `10.50.0.9`" means
client→server packets get `dst = 10.50.0.9` and server→client packets get `src = 10.50.0.9`; the same for ports and for
the client side. Because the key is canonical, one rule covers both directions, and replies keep matching.

Resolution per packet (`replay.Config.pick`): the conversation's rule (which **replaces** the global rewrite for that
conversation) → otherwise the global rewrite → otherwise untouched; with `OnlyConversations`, packets of conversations
without a rule are dropped. In TCP mode a rule also selects which conversation is replayed and supplies the live
endpoints.

## Validation

`NewSet` rejects duplicate rules, IP-family mismatches and port changes on ICMP; the parsers report which part of a
selector is wrong.

## Tests

`conv_test.go` covers key canonicalisation, role detection (including a late SYN), the table cap and selector parsing;
`replay/conv_test.go` checks the end-to-end effect on packets.

Used by: `stats`, `replay`, `gui`, `cmd/pktreplay`.
