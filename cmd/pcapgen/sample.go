package main

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"net/netip"
	"os"

	"github.com/sasha/pktreplay/internal/checksum"
	"github.com/sasha/pktreplay/internal/craft"
)

var (
	macClient  = [6]byte{0xaa, 0xbb, 0xcc, 0x00, 0x00, 0x50}
	macServer  = [6]byte{0xaa, 0xbb, 0xcc, 0x00, 0x00, 0x10}
	macGateway = [6]byte{0xaa, 0xbb, 0xcc, 0x00, 0x00, 0x01}
	ipClient   = netip.MustParseAddr("192.168.1.50")
	ipServer   = netip.MustParseAddr("192.168.1.10")
	ipGateway  = netip.MustParseAddr("192.168.1.1")
	ipSyslog   = netip.MustParseAddr("192.168.1.20")
)

// genSample writes a small, realistic, deterministic capture that opens in
// tshark/Wireshark without warnings: every checksum and length is valid.
//
//	ARP who-has/is-at -> DNS A query/response -> TCP handshake -> HTTP GET and
//	200 response -> FIN teardown -> 3 ICMP echo pairs -> UDP syslog messages
func genSample(path string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	w := bufio.NewWriter(f)
	le := binary.LittleEndian
	hdr := make([]byte, 24)
	le.PutUint32(hdr[0:], 0xa1b2c3d4)
	le.PutUint16(hdr[4:], 2)
	le.PutUint16(hdr[6:], 4)
	le.PutUint32(hdr[16:], 65535)
	le.PutUint32(hdr[20:], 1)
	w.Write(hdr)

	ts := int64(1_763_000_000) * 1_000_000 // µs
	emit := func(gapUs int64, frame []byte) {
		ts += gapUs
		var rec [16]byte
		le.PutUint32(rec[0:], uint32(ts/1_000_000))
		le.PutUint32(rec[4:], uint32(ts%1_000_000))
		le.PutUint32(rec[8:], uint32(len(frame)))
		le.PutUint32(rec[12:], uint32(len(frame)))
		w.Write(rec[:])
		w.Write(frame)
	}
	id := uint16(0x1000)
	nextID := func() uint16 { id++; return id }

	// --- ARP: client asks for the gateway ---
	emit(0, arp(1, macClient, ipClient, [6]byte{}, ipGateway, [6]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}))
	emit(380, arp(2, macGateway, ipGateway, macClient, ipClient, macClient))

	// --- DNS: A record for www.example.test ---
	q := dnsQuery(0x1a2b, "www.example.test")
	emit(4_200, craft.UDP(nil, &craft.Spec{SrcMAC: macClient, DstMAC: macGateway, Src: ipClient, Dst: ipGateway,
		SrcPort: 40000, DstPort: 53, ID: nextID(), Payload: q}))
	emit(8_700, craft.UDP(nil, &craft.Spec{SrcMAC: macGateway, DstMAC: macClient, Src: ipGateway, Dst: ipClient,
		SrcPort: 53, DstPort: 40000, ID: nextID(), Payload: dnsAnswer(q, ipServer)}))

	// --- TCP + HTTP ---
	cSeq, sSeq := uint32(0x2f1a6c10), uint32(0x7d3e9a40)
	c := func(seq, ack uint32, fl uint8, opt, pay []byte) []byte {
		return craft.TCP(nil, &craft.Spec{SrcMAC: macClient, DstMAC: macServer, Src: ipClient, Dst: ipServer,
			SrcPort: 51234, DstPort: 80, Seq: seq, Ack: ack, Flags: fl, Window: 64240, ID: nextID(), Options: opt, Payload: pay})
	}
	s := func(seq, ack uint32, fl uint8, opt, pay []byte) []byte {
		return craft.TCP(nil, &craft.Spec{SrcMAC: macServer, DstMAC: macClient, Src: ipServer, Dst: ipClient,
			SrcPort: 80, DstPort: 51234, Seq: seq, Ack: ack, Flags: fl, Window: 65160, ID: nextID(), Options: opt, Payload: pay})
	}
	synOpts := []byte{2, 4, 0x05, 0xb4, 1, 1, 4, 2, 1, 3, 3, 7} // MSS 1460, NOP NOP SACK-perm, NOP WS 7
	const (
		FIN, SYN, PSH, ACK = 0x01, 0x02, 0x08, 0x10
	)
	emit(150_000, c(cSeq, 0, SYN, synOpts, nil))
	emit(620, s(sSeq, cSeq+1, SYN|ACK, synOpts, nil))
	cSeq++
	sSeq++
	emit(110, c(cSeq, sSeq, ACK, nil, nil))

	req := []byte("GET /index.html HTTP/1.1\r\nHost: www.example.test\r\nUser-Agent: curl/8.5.0\r\nAccept: */*\r\n\r\n")
	emit(900, c(cSeq, sSeq, PSH|ACK, nil, req))
	cSeq += uint32(len(req))
	emit(450, s(sSeq, cSeq, ACK, nil, nil))

	body := "<!doctype html>\n<html><head><title>Sample</title></head>\n<body><h1>pktreplay sample capture</h1>\n" +
		"<p>This page exists only inside a synthetic recording.</p></body></html>\n"
	resp := []byte(fmt.Sprintf("HTTP/1.1 200 OK\r\nServer: nginx/1.24\r\nContent-Type: text/html\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
		len(body), body))
	emit(1_800, s(sSeq, cSeq, PSH|ACK, nil, resp))
	sSeq += uint32(len(resp))
	emit(300, c(cSeq, sSeq, ACK, nil, nil))
	emit(2_000, s(sSeq, cSeq, FIN|ACK, nil, nil))
	sSeq++
	emit(260, c(cSeq, sSeq, FIN|ACK, nil, nil))
	cSeq++
	emit(190, s(sSeq, cSeq, ACK, nil, nil))

	// --- ICMP echo, 3 pairs one second apart ---
	for seq := uint16(1); seq <= 3; seq++ {
		payload := make([]byte, 56)
		for i := range payload {
			payload[i] = byte(0x10 + i)
		}
		gap := int64(1_000_000)
		if seq == 1 {
			gap = 500_000
		}
		emit(gap, icmpEcho(macClient, macGateway, ipClient, ipGateway, 8, 0x0042, seq, payload, nextID()))
		emit(1_300, icmpEcho(macGateway, macClient, ipGateway, ipClient, 0, 0x0042, seq, payload, nextID()))
	}

	// --- UDP syslog ---
	for i, m := range []string{
		"<134>Nov 18 13:20:01 web01 nginx: 192.168.1.50 GET /index.html 200 187",
		"<132>Nov 18 13:20:04 web01 sshd[812]: Failed password for invalid user admin from 192.168.1.77",
		"<134>Nov 18 13:20:09 web01 cron[301]: (root) CMD (run-parts /etc/cron.hourly)",
	} {
		emit(700_000, craft.UDP(nil, &craft.Spec{SrcMAC: macServer, DstMAC: macGateway, Src: ipServer, Dst: ipSyslog,
			SrcPort: uint16(41000 + i), DstPort: 514, ID: nextID(), Payload: []byte(m)}))
	}
	return w.Flush()
}

func arp(op uint16, sMAC [6]byte, sIP netip.Addr, tMAC [6]byte, tIP netip.Addr, ethDst [6]byte) []byte {
	f := make([]byte, 42)
	copy(f[0:6], ethDst[:])
	copy(f[6:12], sMAC[:])
	binary.BigEndian.PutUint16(f[12:], 0x0806)
	binary.BigEndian.PutUint16(f[14:], 1)
	binary.BigEndian.PutUint16(f[16:], 0x0800)
	f[18], f[19] = 6, 4
	binary.BigEndian.PutUint16(f[20:], op)
	copy(f[22:28], sMAC[:])
	a, b := sIP.As4(), tIP.As4()
	copy(f[28:32], a[:])
	copy(f[32:38], tMAC[:])
	copy(f[38:42], b[:])
	return f
}

func dnsName(name string) []byte {
	var out []byte
	start := 0
	for i := 0; i <= len(name); i++ {
		if i == len(name) || name[i] == '.' {
			out = append(out, byte(i-start))
			out = append(out, name[start:i]...)
			start = i + 1
		}
	}
	return append(out, 0)
}

func dnsQuery(id uint16, name string) []byte {
	m := make([]byte, 12)
	binary.BigEndian.PutUint16(m[0:], id)
	binary.BigEndian.PutUint16(m[2:], 0x0100) // recursion desired
	binary.BigEndian.PutUint16(m[4:], 1)
	m = append(m, dnsName(name)...)
	return append(m, 0, 1, 0, 1) // A, IN
}

func dnsAnswer(query []byte, ans netip.Addr) []byte {
	m := append([]byte{}, query...)
	binary.BigEndian.PutUint16(m[2:], 0x8180) // response, recursion available
	binary.BigEndian.PutUint16(m[6:], 1)      // one answer
	a := ans.As4()
	m = append(m, 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0x01, 0x2c, 0, 4) // name ptr, A, IN, TTL 300, len 4
	return append(m, a[:]...)
}

func icmpEcho(sMAC, dMAC [6]byte, src, dst netip.Addr, typ uint8, ident, seq uint16, payload []byte, ipID uint16) []byte {
	icmp := make([]byte, 8, 8+len(payload))
	icmp[0] = typ
	binary.BigEndian.PutUint16(icmp[4:], ident)
	binary.BigEndian.PutUint16(icmp[6:], seq)
	icmp = append(icmp, payload...)
	binary.BigEndian.PutUint16(icmp[2:], checksum.Checksum(icmp))

	f := make([]byte, 14+20+len(icmp))
	copy(f[0:6], dMAC[:])
	copy(f[6:12], sMAC[:])
	binary.BigEndian.PutUint16(f[12:], 0x0800)
	ip := f[14:]
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:], uint16(20+len(icmp)))
	binary.BigEndian.PutUint16(ip[4:], ipID)
	ip[8], ip[9] = 64, 1
	a, b := src.As4(), dst.As4()
	copy(ip[12:16], a[:])
	copy(ip[16:20], b[:])
	checksum.IPv4Header(ip)
	copy(ip[20:], icmp)
	return f
}
