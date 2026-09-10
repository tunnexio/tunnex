package main

import (
	"github.com/tunnexio/tunnex/apps/api/internal/aiegress"
	"log"
	"net/http"
	"os"
	"time"
)

func main() {
	p, e := aiegress.LoadPolicy(os.Getenv("TUNNEX_AI_CUSTOM_ENDPOINTS_FILE"))
	if e != nil {
		log.Fatal("custom egress policy invalid")
	}
	h, e := aiegress.NewServer(p, os.Getenv("TUNNEX_AI_CUSTOM_PROXY_USERNAME"), os.Getenv("TUNNEX_AI_CUSTOM_PROXY_PASSWORD"))
	if e != nil {
		log.Fatal("custom egress credentials invalid")
	}
	listen := os.Getenv("TUNNEX_AI_CUSTOM_PROXY_LISTEN")
	if listen == "" {
		listen = ":8190"
	}
	s := &http.Server{Addr: listen, Handler: h, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 10 * time.Second, MaxHeaderBytes: 8192}
	if s.ListenAndServe() != nil {
		log.Fatal("custom egress stopped")
	}
}
