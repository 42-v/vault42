package oauth2

import (
	"net"
	"net/http"
	"time"
)

// providerTimeout bounds a single call to an identity provider. Every
// constructor in this package already sets it; fallbackClient exists for the
// zero value.
const providerTimeout = 10 * time.Second

// fallbackClient is what a provider built as a struct literal gets instead of
// http.DefaultClient.
//
// The constructors always set the client field, so the nil branch is
// unreachable today — but http.DefaultClient has no timeout and no bounded
// transport, so the day somebody constructs a provider without the constructor
// they get an outbound call that can hang forever holding a goroutine and a
// socket. A zero value that is safe costs one variable.
var fallbackClient = &http.Client{
	Timeout: providerTimeout,
	Transport: &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		MaxConnsPerHost:       64,
		MaxIdleConns:          64,
		MaxIdleConnsPerHost:   8,
		IdleConnTimeout:       90 * time.Second,
		ResponseHeaderTimeout: providerTimeout,
		TLSHandshakeTimeout:   5 * time.Second,
		ExpectContinueTimeout: time.Second,
		ForceAttemptHTTP2:     true,
	},
}
