package main

import (
	"encoding/json"
	"net/http"
	"sync"
)

func main() {
	var mu sync.Mutex
	expected := "fixture-provider-before"
	accepted, rejected := 0, 0
	http.HandleFunc("/control", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if r.Method == "PUT" {
			var p struct {
				Secret string `json:"secret"`
			}
			if json.NewDecoder(r.Body).Decode(&p) != nil || p.Secret == "" {
				http.Error(w, "invalid", 400)
				return
			}
			expected = p.Secret
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]int{"accepted": accepted, "rejected": rejected})
	})
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == "GET" {
			w.Write([]byte(`{"data":[]}`))
			return
		}
		mu.Lock()
		if r.Header.Get("Authorization") != "Bearer "+expected {
			rejected++
			mu.Unlock()
			http.Error(w, "provider credential rejected", 401)
			return
		}
		accepted++
		mu.Unlock()
		w.Write([]byte(`{"id":"rotation-fixture","object":"chat.completion","model":"openai/gpt-4o-mini","choices":[{"index":0,"message":{"role":"assistant","content":"OK"},"finish_reason":"stop"}],"usage":{"prompt_tokens":4,"completion_tokens":1,"total_tokens":5}}`))
	})
	if http.ListenAndServe(":8081", nil) != nil {
		panic("fixture listener failed")
	}
}
