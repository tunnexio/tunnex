package main

import (
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

func query(t *testing.T, name string) []byte {
	t.Helper()
	q := dnsmessage.Message{Header: dnsmessage.Header{ID: 91, RecursionDesired: true}, Questions: []dnsmessage.Question{{Name: dnsmessage.MustNewName(name), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}}}
	packet, err := q.Pack()
	if err != nil {
		t.Fatal(err)
	}
	return packet
}
func TestAnswersAndTruncationCounters(t *testing.T) {
	path := filepath.Join(t.TempDir(), "counts.json")
	r := &receiver{address: [4]byte{10, 73, 0, 10}, countersPath: path}
	for _, tc := range []struct {
		name, transport string
		answers         int
		truncated       bool
		code            dnsmessage.RCode
	}{
		{appName, "udp", 1, false, dnsmessage.RCodeSuccess},
		{aliasName, "tcp", 2, false, dnsmessage.RCodeSuccess},
		{"absent." + zone, "udp", 0, false, dnsmessage.RCodeNameError},
		{truncatedName, "udp", 0, true, dnsmessage.RCodeSuccess},
		{truncatedName, "tcp", 1, false, dnsmessage.RCodeSuccess},
	} {
		packet, err := r.answer(query(t, tc.name), tc.transport)
		if err != nil {
			t.Fatal(err)
		}
		var reply dnsmessage.Message
		if err := reply.Unpack(packet); err != nil {
			t.Fatal(err)
		}
		if reply.ID != 91 || !reply.Response || !reply.Authoritative || reply.RCode != tc.code || reply.Truncated != tc.truncated || len(reply.Answers) != tc.answers {
			t.Fatalf("%s/%s unexpected reply: %+v", tc.name, tc.transport, reply)
		}
		if !tc.truncated && tc.answers > 0 {
			answer, ok := reply.Answers[len(reply.Answers)-1].Body.(*dnsmessage.AResource)
			if !ok || answer.A != [4]byte{10, 73, 0, 10} {
				t.Fatal("A answer escaped owned emulator target")
			}
		}
		if tc.name == aliasName {
			cname, ok := reply.Answers[0].Body.(*dnsmessage.CNAMEResource)
			if !ok || cname.CNAME.String() != appName {
				t.Fatal("alias did not point to owned app")
			}
		}
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var result struct {
		Version int
		Counts  map[string]queryCounts
	}
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatal(err)
	}
	if result.Version != 1 || result.Counts["udp:"+truncatedName].Truncated != 1 || result.Counts["tcp:"+truncatedName].Answers != 1 || result.Counts["udp:absent."+zone].NXDomain != 1 {
		t.Fatalf("missing wire evidence: %+v", result)
	}
}
func TestTCPFramingAndMalformedQuery(t *testing.T) {
	r := &receiver{address: [4]byte{10, 73, 0, 10}}
	server, client := net.Pipe()
	defer client.Close()
	go serveTCP(r, server)
	packet := query(t, appName)
	frame := make([]byte, 2, len(packet)+2)
	binary.BigEndian.PutUint16(frame, uint16(len(packet)))
	frame = append(frame, packet...)
	go func() { _, _ = client.Write(frame) }()
	var length [2]byte
	if _, err := io.ReadFull(client, length[:]); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, binary.BigEndian.Uint16(length[:]))
	if _, err := io.ReadFull(client, reply); err != nil {
		t.Fatal(err)
	}
	var msg dnsmessage.Message
	if err := msg.Unpack(reply); err != nil || len(msg.Answers) != 1 {
		t.Fatalf("bad TCP answer: %v", err)
	}
	if _, err := r.answer([]byte{1, 2, 3}, "udp"); err == nil {
		t.Fatal("malformed query accepted")
	}
}
