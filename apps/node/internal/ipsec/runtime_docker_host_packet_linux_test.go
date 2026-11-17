//go:build linux

package ipsec

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"testing"
	"time"
)

// Only disposable native harness containers set this gate. No daemon/policy writes.
func TestDockerHostNativePacketEndpoint(t *testing.T) {
	if os.Getenv("TUNNEX_DOCKER_HOST_PACKET") != "1" {
		t.Skip("owned native Docker fixture only")
	}
	role := os.Getenv("TUNNEX_PACKET_ROLE")
	if role == "server" {
		for _, ports := range [][2]string{{"18080", "18081"}, {"18082", "18083"}} {
			tcp, e := net.Listen("tcp4", "10.20.0.2:"+ports[0])
			if e != nil {
				t.Fatal(e)
			}
			defer tcp.Close()
			udp, e := net.ListenPacket("udp4", "10.20.0.2:"+ports[1])
			if e != nil {
				t.Fatal(e)
			}
			defer udp.Close()
			go func() {
				b := make([]byte, 4096)
				for {
					n, a, e := udp.ReadFrom(b)
					if e != nil {
						return
					}
					udp.WriteTo(b[:n], a)
				}
			}()
			go func() {
				for {
					c, e := tcp.Accept()
					if e != nil {
						return
					}
					go func() {
						defer c.Close()
						b := make([]byte, 4096)
						for {
							n, e := c.Read(b)
							if n > 0 {
								c.Write(b[:n])
							}
							if e != nil {
								return
							}
						}
					}()
				}
			}()
		}
		fmt.Println("DOCKER_NATIVE_ENDPOINT_READY")
		time.Sleep(180 * time.Second)
		return
	}
	if role != "client" {
		t.Fatal("unknown endpoint role")
	}
	proto := os.Getenv("TUNNEX_PACKET_PROTOCOL")
	address := "10.20.0.2:18080"
	if proto == "udp" {
		address = "10.20.0.2:18081"
	} else if proto != "tcp" {
		t.Fatal("protocol")
	}
	if os.Getenv("TUNNEX_PACKET_WRONGPORT") == "1" {
		if proto == "tcp" {
			address = "10.20.0.2:18082"
		} else {
			address = "10.20.0.2:18083"
		}
	}
	payload := []byte("owned-docker-native-" + os.Getenv("TUNNEX_PACKET_NONCE"))
	if len(payload) != 84 {
		t.Fatal("fresh64hex nonce required")
	}
	if _, e := hex.DecodeString(os.Getenv("TUNNEX_PACKET_NONCE")); e != nil {
		t.Fatal("nonce")
	}
	c, e := net.DialTimeout(proto+"4", address, 2*time.Second)
	if e == nil {
		defer c.Close()
		c.SetDeadline(time.Now().Add(2 * time.Second))
		_, e = c.Write(payload)
	}
	b := make([]byte, 4096)
	n := 0
	if e == nil {
		if proto == "tcp" {
			n, e = io.ReadFull(c, b[:len(payload)])
		} else {
			n, e = c.Read(b)
		}
	}
	matched := e == nil && string(b[:n]) == string(payload)
	fmt.Printf("PACKET protocol=%s matched=%t expected_sha256=%x received_sha256=%x\n", proto, matched, sha256.Sum256(payload), sha256.Sum256(b[:n]))
	if matched != (os.Getenv("TUNNEX_PACKET_EXPECT") == "allow") {
		t.Fatal("native packet outcome mismatch")
	}
}

func TestDockerHostNativeEncryptedCounters(t *testing.T) {
	if os.Getenv("TUNNEX_DOCKER_HOST_PACKET") != "1" {
		t.Skip("owned native fixture only")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, e := NewDaemonClient("/run/tunnex-ipsec/charon.vici")
	if e != nil {
		t.Fatal(e)
	}
	v, e := c.Inspect(ctx)
	if e != nil {
		t.Fatal(e)
	}
	type row struct {
		Name                                  string
		ReqID, IfIDIn, IfIDOut, SPIIn, SPIOut uint32
		BytesIn, BytesOut                     uint64
	}
	rows := []row{}
	for _, sa := range v.SAs {
		for _, ch := range sa.Children {
			if !sa.Established || !ch.Installed {
				t.Fatal("unhealthy native child")
			}
			rows = append(rows, row{sa.Name, ch.ReqID, ch.IfIDIn, ch.IfIDOut, ch.SPIIn, ch.SPIOut, ch.BytesIn, ch.BytesOut})
		}
	}
	if len(rows) != 2 {
		t.Fatal("exact two native children required")
	}
	b, e := json.Marshal(rows)
	if e != nil {
		t.Fatal(e)
	}
	fmt.Println("ENCRYPTED_COUNTERS " + string(b))
}
