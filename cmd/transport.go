package cmd

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"time"

	xhttp "github.com/minio/minio/cmd/http"
	xrpc "github.com/minio/minio/cmd/rpc"
)

func newCustomDialContext(timeout time.Duration) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		dialer := &net.Dialer{
			Timeout:   timeout,
			KeepAlive: timeout,
			DualStack: true,
		}

		conn, err := dialer.DialContext(ctx, network, addr)
		if err != nil {
			return nil, err
		}

		return xhttp.NewTimeoutConn(conn, timeout, timeout), nil
	}
}

// DefaultTransport is exactly same as Go default in https://golang.org/pkg/net/http/#RoundTripper
// except custom DialContext.
var DefaultTransport = &http.Transport{
	Proxy:                 http.ProxyFromEnvironment,
	DialContext:           newCustomDialContext(xrpc.DefaultRPCTimeout),
	MaxIdleConns:          1024,
	MaxIdleConnsPerHost:   1024,
	IdleConnTimeout:       30 * time.Second,
	TLSHandshakeTimeout:   10 * time.Second,
	ExpectContinueTimeout: 1 * time.Second,
	TLSClientConfig:       &tls.Config{RootCAs: globalRootCAs},
	DisableCompression:    true,
}
