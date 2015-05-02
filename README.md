# go-forwarded

`forwarded` is a Golang decorator/wrapper for [http.Handler](https://golang.org/pkg/net/http/#Handler)
that parses `X-Forwarded-For` and `X-Forwarded-Protocol`-alike headers and updates passing
[http.Request.RemoteAddr](https://golang.org/pkg/net/http/#Request) and
[http.Request.TLS](https://golang.org/pkg/net/http/#Request) accordingly.

It supports arbitrary named individual headers and [RFC7239](http://tools.ietf.org/html/rfc7239) `Forwarded` header.
