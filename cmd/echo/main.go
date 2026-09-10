// Command echo is a tiny demo backend. It answers with the request headers and
// path it received, which makes the Nginx auth_request integration observable:
// the X-User-* headers injected by the proxy show up in the response.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

func main() {
	addr := flag.String("addr", ":8080", "listen address")
	flag.Parse()

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintln(w, `{"status":"ok"}`)
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		headers := make(map[string]string, len(r.Header))
		for name, values := range r.Header {
			headers[strings.ToLower(name)] = strings.Join(values, ",")
		}
		response := map[string]any{
			"service":     "echo-backend",
			"method":      r.Method,
			"path":        r.URL.Path,
			"query":       r.URL.RawQuery,
			"headers":     headers,
			"received_at": time.Now().UTC().Format(time.RFC3339),
		}
		w.Header().Set("Content-Type", "application/json")
		encoder := json.NewEncoder(w)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(response); err != nil {
			log.Printf("encode response: %v", err)
		}
	})

	server := &http.Server{
		Addr:              *addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      10 * time.Second,
	}
	log.Printf("echo backend listening on %s", *addr)
	if err := server.ListenAndServe(); err != nil {
		log.Printf("echo backend stopped: %v", err)
		os.Exit(1)
	}
}
