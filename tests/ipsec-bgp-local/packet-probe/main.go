package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"time"
)

func main() {
	if len(os.Args) < 3 {
		panic("server <listen> or client <target> <source> <allow|deny>")
	}
	switch os.Args[1] {
	case "server":
		l, err := net.Listen("tcp4", os.Args[2])
		if err != nil {
			panic(err)
		}
		fmt.Println("OWNED_TARGET_READY")
		for {
			c, err := l.Accept()
			if err != nil {
				panic(err)
			}
			go func(c net.Conn) { defer c.Close(); c.SetDeadline(time.Now().Add(5 * time.Second)); io.Copy(c, c) }(c)
		}
	case "client":
		if len(os.Args) != 5 {
			panic("client requires target source expectation")
		}
		ip := net.ParseIP(os.Args[3])
		if ip == nil || ip.To4() == nil {
			panic("IPv4 source required")
		}
		if os.Args[4] != "allow" && os.Args[4] != "deny" {
			panic("invalid expectation")
		}
		d := net.Dialer{Timeout: 2 * time.Second, LocalAddr: &net.TCPAddr{IP: ip}}
		c, err := d.Dial("tcp4", os.Args[2])
		if os.Args[4] == "deny" {
			if err == nil {
				c.Close()
				panic("unexpected forwarded connectivity")
			}
			fmt.Println("OWNED_FORWARDED_TARGET_DENIED")
			return
		}
		if err != nil {
			panic(err)
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(2 * time.Second))
		nonce := make([]byte, 32)
		if _, err = rand.Read(nonce); err != nil {
			panic(err)
		}
		nonceHex := hex.EncodeToString(nonce)
		payload := []byte("tunnex-integrated-forward-proof:" + nonceHex)
		if _, err = c.Write(payload); err != nil {
			panic(err)
		}
		got := make([]byte, len(payload))
		if _, err = io.ReadFull(c, got); err != nil {
			panic(err)
		}
		if !bytes.Equal(got, payload) {
			panic("response mismatch")
		}
		sum := sha256.Sum256(got)
		fmt.Printf("OWNED_FORWARDED_TARGET_ALLOWED nonce=%s response_sha256=%x\n", nonceHex, sum)
	default:
		panic("unknown mode")
	}
}
