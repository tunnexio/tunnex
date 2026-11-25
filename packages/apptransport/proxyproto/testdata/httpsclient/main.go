// httpsclient sends one HTTPS request with caller-chosen (forged) client
// address headers and prints the response body. Built only by
// tests/console-client-ip/walk.sh.
package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"os"
)

func main() {
	target, host := os.Args[1], os.Args[2]
	c, err := net.Dial("tcp", target)
	if err != nil {
		fmt.Println("dial-error")
		os.Exit(1)
	}
	t := tls.Client(c, &tls.Config{ServerName: host, InsecureSkipVerify: true})
	fmt.Fprintf(t, "GET /api/v1/whoami HTTP/1.1\r\nHost: %s\r\nTrue-Client-IP: 6.6.6.6\r\nX-Real-IP: 7.7.7.7\r\nX-Forwarded-For: 8.8.8.8\r\nConnection: close\r\n\r\n", host)
	b, _ := io.ReadAll(t)
	fmt.Print(string(b))
}
