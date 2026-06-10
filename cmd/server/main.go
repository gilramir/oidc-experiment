// Command server is a tiny JSON-RPC-over-TCP server that authenticates every
// request with an OIDC access token. The verification logic lives in
// internal/server; this is just flag parsing and the listen loop.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"

	"github.com/gilbertr/oidc-experiment/internal/server"
)

func main() {
	port := flag.Int("port", 8888, "TCP port to listen on")
	issuer := flag.String("issuer", "http://127.0.0.1:5556/dex", "OIDC issuer URL")
	clientID := flag.String("client-id", "oidc-experiment-cli", "expected token audience (client id)")
	flag.Parse()

	srv, err := server.New(context.Background(), *issuer, *clientID)
	if err != nil {
		log.Fatal(err)
	}

	addr := fmt.Sprintf(":%d", *port)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("listen on %s: %v", addr, err)
	}
	log.Printf("listening on %s (issuer %s)", addr, *issuer)
	log.Fatal(srv.Serve(ln))
}
