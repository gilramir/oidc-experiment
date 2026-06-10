This repo is for doing an experiment with oidc authentication.

We want a simple server written in Go,  which accepts TCP connections and
speaks a simple JSON-RPC protocol. By default is listens on port 8888,
but it can be chosen on the command-line.

The first "method" it honors is "time"; it will return the time in RFC3389
format.

We want a simple client program written in Go. (so, two programs in this repo).
It will talk to this server and ask for a method. The method name is given on
the CLI. Of course, the only valid option right now is "time".

This experiment is about OIDC authentication. I would like the client to get
credentials from an oidc server and pass them along in this request, perhaps
as another fields in the json-rpc payload. I want the server to check
the credentials and allow any valid, authenticated user, and reject any
anonymous message. If the credentials are invalid, the server should reject the
message. Rejected messages turn into responses that indicate the rejection.
