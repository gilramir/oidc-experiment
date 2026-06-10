// Package rpc defines the tiny JSON-RPC 2.0 message shapes shared by the
// client and server. One request and one response are exchanged per TCP
// connection, each encoded as a single JSON object.
package rpc

import "encoding/json"

// Request is a JSON-RPC request. The Token field is our extension: it carries
// the OAuth2 access token (a JWT) that the server validates before running the
// method. An empty Token means the request is anonymous and will be rejected.
type Request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      int             `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
	Token   string          `json:"token,omitempty"`
}

// Response is a JSON-RPC response. Exactly one of Result or Error is set.
type Response struct {
	JSONRPC string      `json:"jsonrpc"`
	ID      int         `json:"id"`
	Result  interface{} `json:"result,omitempty"`
	Error   *Error      `json:"error,omitempty"`
}

// Error is a JSON-RPC error object.
type Error struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// Standard-ish error codes used by this experiment.
const (
	CodeMethodNotFound = -32601 // JSON-RPC reserved: unknown method
	CodeUnauthorized   = -32001 // our app code: missing/invalid/expired token
)
