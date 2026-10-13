// Local emulation fixture only. Uses the node module's locked DNS codec; no forwarding.
package main

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

const zone = "localemulated.gcp.lab.test."
const appName = "app." + zone
const aliasName = "alias." + zone
const truncatedName = "tcp." + zone

type queryCounts struct {
	Queries   uint64 `json:"queries"`
	Answers   uint64 `json:"answers"`
	Truncated uint64 `json:"truncated"`
	NXDomain  uint64 `json:"nxdomain"`
}
type receiver struct {
	mu           sync.Mutex
	address      [4]byte
	countersPath string
	counts       map[string]queryCounts
}

func (r *receiver) answer(packet []byte, transport string) ([]byte, error) {
	var q dnsmessage.Message
	if err := q.Unpack(packet); err != nil {
		return nil, err
	}
	if q.Response || q.OpCode != 0 || len(q.Questions) != 1 {
		return nil, errors.New("expected one ordinary DNS question")
	}
	question := q.Questions[0]
	name := strings.ToLower(question.Name.String())
	reply := dnsmessage.Message{Header: dnsmessage.Header{ID: q.ID, Response: true, Authoritative: true, RecursionDesired: q.RecursionDesired}, Questions: q.Questions}
	known := name == appName || name == aliasName || name == truncatedName
	if question.Class != dnsmessage.ClassINET {
		reply.RCode = dnsmessage.RCodeRefused
	} else if !known {
		reply.RCode = dnsmessage.RCodeNameError
	} else if transport == "udp" && name == truncatedName {
		reply.Truncated = true
	} else {
		header := dnsmessage.ResourceHeader{Name: question.Name, Class: dnsmessage.ClassINET, TTL: 5}
		if name == aliasName && (question.Type == dnsmessage.TypeA || question.Type == dnsmessage.TypeCNAME) {
			header.Type = dnsmessage.TypeCNAME
			reply.Answers = append(reply.Answers, dnsmessage.Resource{Header: header, Body: &dnsmessage.CNAMEResource{CNAME: dnsmessage.MustNewName(appName)}})
		}
		if question.Type == dnsmessage.TypeA {
			header.Type = dnsmessage.TypeA
			if name == aliasName {
				header.Name = dnsmessage.MustNewName(appName)
			}
			reply.Answers = append(reply.Answers, dnsmessage.Resource{Header: header, Body: &dnsmessage.AResource{A: r.address}})
		}
	}
	payload, err := reply.Pack()
	if err != nil {
		return nil, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.counts == nil {
		r.counts = make(map[string]queryCounts)
	}
	key := transport + ":" + name
	count := r.counts[key]
	count.Queries++
	count.Answers += uint64(len(reply.Answers))
	if reply.Truncated {
		count.Truncated++
	}
	if reply.RCode == dnsmessage.RCodeNameError {
		count.NXDomain++
	}
	r.counts[key] = count
	if r.countersPath != "" {
		data, err := json.MarshalIndent(struct {
			Version int                    `json:"version"`
			Counts  map[string]queryCounts `json:"counts"`
		}{1, r.counts}, "", "  ")
		if err != nil {
			return nil, err
		}
		// A dedicated fixture path, replaced atomically; never use a production path.
		if err := os.WriteFile(r.countersPath+".tmp", append(data, '\n'), 0600); err != nil {
			return nil, err
		}
		if err := os.Rename(r.countersPath+".tmp", r.countersPath); err != nil {
			return nil, err
		}
	}
	return payload, nil
}

func serveTCP(r *receiver, c net.Conn) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	var length [2]byte
	if _, err := io.ReadFull(c, length[:]); err != nil {
		return
	}
	size := binary.BigEndian.Uint16(length[:])
	if size < 12 || size > 4096 {
		return
	}
	packet := make([]byte, size)
	if _, err := io.ReadFull(c, packet); err != nil {
		return
	}
	reply, err := r.answer(packet, "tcp")
	if err != nil {
		return
	}
	binary.BigEndian.PutUint16(length[:], uint16(len(reply)))
	_, _ = io.Copy(c, strings.NewReader(string(append(length[:], reply...))))
}

func main() {
	listen := flag.String("listen", "127.0.0.1:1053", "explicit owned lab DNS bind address (UDP and TCP)")
	answerIP := flag.String("answer-ip", "10.73.0.10", "A record for app/alias/tcp fixture names")
	counters := flag.String("counters", "", "dedicated JSON counters file; parent directory must exist")
	flag.Parse()
	ip, err := netip.ParseAddr(*answerIP)
	if err != nil || !ip.Is4() || !ip.IsPrivate() {
		fmt.Fprintln(os.Stderr, "answer-ip must be private IPv4")
		os.Exit(2)
	}
	r := &receiver{address: ip.As4(), countersPath: *counters}
	tcp, err := net.Listen("tcp", *listen)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer tcp.Close()
	udp, err := net.ListenPacket("udp", tcp.Addr().String())
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer udp.Close()
	go func() {
		buf := make([]byte, 4096)
		for {
			n, peer, err := udp.ReadFrom(buf)
			if err != nil {
				return
			}
			reply, err := r.answer(buf[:n], "udp")
			if err == nil {
				_, _ = udp.WriteTo(reply, peer)
			}
		}
	}()
	slots := make(chan struct{}, 32)
	go func() {
		for {
			c, err := tcp.Accept()
			if err != nil {
				return
			}
			select {
			case slots <- struct{}{}:
				go func() { defer func() { <-slots }(); serveTCP(r, c) }()
			default:
				_ = c.Close()
			}
		}
	}()
	fmt.Printf("Local emulation DNS receiver %s; zone %s; UDP TC name %s\n", tcp.Addr(), zone, truncatedName)
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	<-stop
}
