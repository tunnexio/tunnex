// clientipecho reports the client address the API router derives (chi RealIP,
// as in NewRouter). Built only by tests/console-client-ip/walk.sh.
package main

import (
	"fmt"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

func main() {
	r := chi.NewRouter()
	r.Use(middleware.RealIP)
	r.HandleFunc("/*", func(w http.ResponseWriter, r *http.Request) { fmt.Fprintf(w, "api-sees=%s\n", r.RemoteAddr) })
	_ = http.ListenAndServe(":8080", r)
}
